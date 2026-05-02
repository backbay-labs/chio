# Milestone 03: Hosted CI Truth + Reproducible Builds

## Lens

Single lens: release legibility. trajectory-2 closed with hosted CI in
admin-merge bypass mode (billing exhausted on 2026-04-26T23:00Z; the
workspace one-liner runs locally only); the workspace verdict treats
that bypass as load-bearing debt that disqualifies any external
evidence still on offer. M03 ends the bypass and replaces it with a
real hosted CI lane plus a reproducible-build pipeline whose
checksums are externally reproduced by an independent third party.
Every other trajectory-3 milestone consumes the CI signal M03
restores; M02 partner-facing artifacts, M04 mutation-gate flip, M05
threat-coverage-gate flip, M06 cargo-vet / SBOM, M08 audit memo, M09
HITRUST evidence, and M10 Bedrock marketplace conformance all wait
on this lane. There is no secondary lens (no perf, no security, no
formal). Proposals that pull a second lens are out of scope and
should be deferred to a follow-on.

## Why this is on the trajectory

**Release-gate anchor:** RELEASE_AUDIT

trajectory-2 shipped a CI workflow set covering Rust build / lint /
test, cargo-vet, cargo-deny, MSRV, freeze-guard, bench-regression,
formal-tla, kani-public-pr, mutation-testing, fuzz, replay-gate,
SLSA L3 generator, and release-binaries (five targets). All of it
parses and triggers; none of it has run since 2026-04-26T23:00Z. The
GitHub Actions account hit a billing failure that fails every job at
runner-start with the canonical billing string "The job was not
started because recent account payments have failed or your spending
limit needs to be increased." Sample of the last 500 runs
(`gh run list --limit 500`): 489 failure, 10 cancelled, 1 success.
Total runs reported by the API since then: 6,865.

In the same window, 118 PRs (#306-#425) were merged via admin
override after every required check came back red. Spot-check of
PR #425: 28 status checks, 25 failed, 1 cancelled, 1 skipped, 1
success ("Cursor Bugbot"). The 25 failures included every
load-bearing gate the branch ruleset names as required ("Build,
lint, test", "MSRV build and test", "cargo-vet (supply-chain audit)",
"cargo-deny (supply-chain bans/advisories/licenses)", "freeze-guard",
"bench-regression", "formal-tla (apalache safety)",
"kani-public-pr (lanes.pr harnesses)", per-language replay-gate,
arena-determinism, header-stamp, vectors-byte-stable,
cross-lang-bytes). All 118 PRs are admin-merges; the workspace
one-liner ran locally on the author's machine, not on a hosted
runner.

The verdict's release-audit anchor reads this state as
non-negotiable. The M08 vendor-evidence reviewer (NCC Group / Trail
of Bits shortlist), the M09 HITRUST i1 assessor, and the M10 AWS
Bedrock marketplace reviewer all expect a green hosted CI signal on
the v3.18 release commit plus a reproducible-build hash that an
external party has matched. M03 ships both. The rest of trajectory-3
is downstream of M03.P1 (billing restored + workflows re-enabled);
P1 is the single highest-leverage ticket in the trajectory.

The reproducible-build half of M03 fills a gap inherited from
trajectory-2: `release-binaries.yml` already builds five targets,
emits `*.sha256`, signs blobs with cosign, and uploads a
`release-metadata.json` carrying `release_tag`, `source_ref`,
`source_sha`, but nothing in the lane verifies that a second build
on a fresh runner with the same toolchain pin yields the same digest.
`rustc` floats on `rustup toolchain install stable`. There is no
`SOURCE_DATE_EPOCH`. There is no `[profile.release]` block pinning
`codegen-units = 1`, `lto = "fat"`, `strip = "symbols"`. The SLSA L3
generator (`slsa.yml`) is wired through the
`slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml`
reusable workflow, pinned at SHA `f7dd8c54...`, but it has never
been exercised end-to-end against a real tag because billing has
been failing since before the first scheduled release. M03 brings
all four (toolchain pin, `SOURCE_DATE_EPOCH`, profile pins, two-
builder hash compare) on line for Linux x86_64 and exercises the
full chain on the v3.18 retroactive cert in P5.

## Prior-art reckoning

trajectory-2 already shipped:

- `.github/workflows/ci.yml` (553 lines) carrying the required-check
  set: `Build, lint, test`, `MSRV build and test`,
  `cargo-vet (supply-chain audit)`,
  `cargo-deny (supply-chain bans/advisories/licenses)`. The header
  comment names the required vs. advisory lanes. M03 does not rewrite
  ci.yml; it re-enables it (billing) and bisects bypass-hidden
  failures.
- `.github/workflows/release-binaries.yml` (884 lines) building five
  targets: `x86_64-unknown-linux-gnu` (ubuntu-latest),
  `aarch64-unknown-linux-gnu` (cross-rs, ubuntu-latest, cross image
  pinned by SHA `7f8308a8...`), `x86_64-apple-darwin`
  (macos-15-intel), `aarch64-apple-darwin` (macos-14),
  `x86_64-pc-windows-msvc` (windows-latest). Emits per-archive
  `*.sha256` and cosign signatures (`*.sig`, `*.pem`). syft pinned
  by SHA per platform (`066c25...` linux, `223f5a...` darwin-amd64,
  `bc5ad2...` darwin-arm64). M03 preserves it; reproducible-build is
  a sibling workflow, not a fork.
- `.github/workflows/slsa.yml` (132 lines) wiring the SLSA L3
  reusable generator on `workflow_run` after release-binaries
  succeeds. Owned by M09 per `OWNERS.toml`. M03 verifies it end-to-
  end against a real tag and adds a public checksum index that
  cites the Rekor UUID emitted by the reusable generator.
- `.github/workflows/mutants.yml` (402 lines) scaffolded with
  advisory `mutants-pr` and `mutants-nightly` jobs gated by
  `releases.toml`. Today `cycle_end_tag` is empty and
  `observed_consecutive_nightly_successes` is 0; the gate stays
  advisory until M04 flips it. M03 does not touch the gate; M03
  ensures the nightly job actually runs.
- The trust-boundary check workflows (`m05-freeze-guard.yml`,
  `bench-regression.yml`, `chio-replay-gate.yml`,
  `chio-arena-determinism.yml`, `chio-tee-image.yml`, `slsa.yml`,
  `verdict-matrix.yml`, `conformance-matrix.yml`,
  `provider-conformance.yml`, `threat-model-coverage.yml`). M03
  preserves all of them; the bisect in P2 surfaces any that have
  silently regressed during the bypass window.

What M03 changes:

- Hosted CI billing restored (operational, not code).
- CI workflows re-enabled and bypass-hidden failures bisected and
  triaged to owning milestones (P2).
- New `.github/workflows/reproducible-build.yml` that runs two
  Linux x86_64 builds on independent runner instances with
  `SOURCE_DATE_EPOCH` derived from the tag commit time, an exact
  rustc version pin, and a third gate job that downloads both
  artifacts and compares sha256.
- New `[profile.release]` block in workspace `Cargo.toml` pinning
  `codegen-units = 1`, `lto = "fat"`, `strip = "symbols"`, plus a
  `rust-toolchain.toml` pinning `stable` to an exact version
  (`1.85.0` for v3.18; reviewed at every cycle-end tag).
- New public checksum index at `supply-chain/checksums/v<tag>.txt`
  emitted by `release-binaries.yml`, cosign-signed, citing the
  Rekor UUID emitted by the SLSA L3 generator as the witness.
- New `scripts/rebuild-from-source.sh` plus an `audits` ledger
  entry naming the third-party rebuilder, the matched hash, and
  the date.

What M03 deliberately does not do:

- Does not move to self-hosted runners. D13 picks GitHub-hosted
  (ubuntu-24.04 + macos-14); runner ops cost is too high during a
  customer pilot.
- Does not promise reproducibility on macOS or Windows. v3.18
  reproducibility is scoped to Linux x86_64 only; macOS (codesign
  timestamps) and Windows (PE COFF timestamps) carry known non-
  determinism that is out of scope for v3.18 and called out in the
  audit doc.
- Does not flip the mutation gate (M04 owns) or the threat-coverage
  gate (M05 owns). M03 ensures the underlying nightly runs execute,
  which has been impossible during the bypass.
- Does not chase third-party runners (BuildJet, Namespace.so, Depot,
  RunsOn). The cost-ground-truthing in the M03 research doc names
  these as a trajectory-3 follow-up if Actions billing turns out to
  be the bottleneck after restoration; M03 does not block on it.
- Does not consolidate hosted-runner billing onto a Backbay org
  account. The repo lives at `github.com/bb-connor/arc` (personal).
  Org migration is a separate trajectory; M03 records the
  ownership question in the audit doc.

## Hard counts (measured 2026-04-30)

Reproduce-with-this-command numbers anchored to live state at the
time of writing. Re-run after each phase merges and update.

- PRs in the admin-merge bypass range #306-#425: 118.
  (`gh pr list --state merged --limit 200 --json number,mergedAt | jq '[.[] | select(.number >= 306 and .number <= 425)] | length'`)
- Bypass start: 2026-04-26T23:00:42Z (first run cluster failure
  after the last green run). First merge in range: PR #306 at
  2026-04-29T18:09:28Z. Last merge in range: PR #425 at
  2026-05-01T07:51:38Z.
- Days since admin-merge bypass began (P0 close, 2026-04-30): 4.
  (Less than one week. The audit-doc field reads "0" until 7 days
  elapse.)
- Workflow runs reported by the GitHub API since the billing trip:
  6,865 total; sample of last 500 = 489 failure, 10 cancelled, 1
  success. (`gh run list --limit 500 --json conclusion | jq -r '.[].conclusion' | sort | uniq -c`)
- CI workflow files YAML-disabled: 0. All 41 files in
  `.github/workflows/` parse and trigger on push / PR / schedule.
  They fail at the runner-start gate because of billing, not
  because the file is commented out. (`ls .github/workflows/*.yml | wc -l`)
- Workflow files non-functional due to billing: 41 (all of them).
- Required-check checks in the branch ruleset that today report
  red: 6. (`Build, lint, test`, `MSRV build and test`,
  `cargo-vet (supply-chain audit)`,
  `cargo-deny (supply-chain bans/advisories/licenses)`,
  `freeze-guard`, `bench-regression`).
- Last green hosted-CI run on `main` before bypass:
  2026-04-26T19:48Z (last `Chio C++ SDK` success). Failing-test
  count at that run is deferred to P1 (`gh run view --log-failed`
  is not callable while billing is failing).
- Per-PR full-CI-sweep cost estimate after restoration: $3-$5 paid
  Actions (cold cache `Build, lint, test` 30 min ubuntu-latest
  $0.24; `Coverage` up to 180 min $1.44; `MSRV` 15 min $0.12;
  `cargo-vet`, `cargo-deny` 10 min each $0.16 combined;
  `formal-tla`, `kani-public-pr` 30-45 min each up to $0.72).
- Rolling cost at trajectory-3 cadence (10 PRs/day): $30-$50/day.

[TODO IMPLEMENT P0 close: failing-tests count at last green
hosted-CI run before bypass (defer until billing is restored and
historical run logs are fetchable).]

[TODO IMPLEMENT P2 close: bypass-bisect surfaced regressions count
plus owning-milestone routing.]

[TODO IMPLEMENT P3 close: byte-identical Linux-x86_64 build hash
for v3.18; mismatched targets if any.]

[TODO IMPLEMENT P4 close: third-party rebuilder identity, matched
hash, and date.]

## Workspace dependency state

No new Rust crate pins.

New tooling pins introduced by this milestone, with rationale:

- `rust-toolchain.toml` pinning `channel = "1.85.0"` for the
  reproducible-build workflow. Today `ci.yml` runs
  `rustup toolchain install stable --profile minimal --component rustfmt --component clippy`,
  which floats. M03 P3 lands the toolchain file pinned to the exact
  version that v3.18 ships against; PR-tier CI continues on rolling
  stable to keep the ergonomic surface for contributors. The
  reproducible-build lane reads the toolchain file directly.
- `[profile.release]` block in workspace `Cargo.toml`:
  `codegen-units = 1`, `lto = "fat"`, `strip = "symbols"`,
  `panic = "abort"` (already present per the existing release
  profile shape; verified at P3.T1). Determinism dampener; not a
  reproducibility silver bullet but removes the largest sources of
  drift.
- `cosign` is already used by `release-binaries.yml`. M03 reuses it
  for `supply-chain/checksums/v<tag>.txt.sig`; no new pin.
- `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`
  is already pinned at `slsa.yml:124`. M03 verifies it end-to-end
  against a real tag in P4.T1; no pin change.
- `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5`,
  `actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830`,
  `actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093`
  are already SHA-pinned. M03 reuses them.

The new workflow files
(`.github/workflows/reproducible-build.yml`) carry the same SHA-pin
discipline as the existing trajectory-2 set. The audit doc carries
a one-line rationale per pin.

## Scope

### In

- Hosted CI billing restored on the GitHub account that currently
  owns `bb-connor/arc`; runner-start gate clears.
- A pinned spending cap on the billing account so the same trip
  cannot recur silently.
- CI workflow re-enablement plus a bisect of the 118 admin-merged
  PRs in #306-#425. Surfaced regressions are routed to their
  owning milestones; M03 does not fix every regression.
- New `.github/workflows/reproducible-build.yml` for Linux x86_64
  with two independent builder jobs and a third hash-compare gate.
- Pinned `rust-toolchain.toml` and `[profile.release]` block.
- `SOURCE_DATE_EPOCH` derived from the tag commit time and threaded
  through every build step.
- `supply-chain/checksums/v<tag>.txt` emitted by
  `release-binaries.yml`, cosign-signed, citing the Rekor UUID.
- Independent third-party rebuild plus matched-hash audit ledger.
- v3.18 release commit retroactively certified: hosted CI green;
  reproducible-build hash published; SLSA L3 attestation present.

### Out (and why)

- Self-hosted runners (D13 picks GitHub-hosted; runner ops cost is
  too high during a customer pilot).
- Third-party hosted runners (BuildJet, Namespace.so, Depot,
  RunsOn). Deferred to trajectory-4 if cost becomes the bottleneck.
- Reproducible builds for macOS and Windows. Known non-determinism
  (codesign timestamps, PE COFF timestamps) places these out of
  scope for v3.18; the audit doc records the carve-out and flags
  them as trajectory-4 candidates.
- Org migration of the hosted-CI billing account. Personal account
  ownership stays for v3.18; org migration is a separate
  trajectory.
- Build-from-source verification by every consumer. M03 ships the
  pipeline plus one third-party rebuild; broader verification is
  consumer-side.
- Promotion of the JSON-RPC numeric-code registry into the URN
  registry (M01 owns; out of M03's lens).
- Mutation-gate flip (M04 owns) and threat-coverage-gate flip (M05
  owns). M03 ensures their nightly runs execute.

## Phases

### P0 - Audit baseline + billing-restoration plan + rebuilder pre-name

P0 lands the audit doc with starting hard counts, formalises the
billing-restoration runbook, and pre-names the third-party
rebuilder so lead time does not bottleneck P4.

- M03.P0.T1 - Open `.planning/trajectory-3/audits/M03-ci-restoration.md`
  with section-2 hard counts filled (4 days since bypass; 0
  workflows YAML-disabled but 41 account-blocked; 118 PRs in
  #306-#425; 6,865 workflow runs since trip; failing-test count
  deferred). Cite paths and commands so the numbers are
  reproducible.
- M03.P0.T2 - Author `docs/runbooks/ci-billing.md` formalising the
  unblocking step (billing-account owner logs in to
  https://github.com/settings/billing; if card decline, update
  payment method; if spending limit, raise cap; verify with one
  push or `gh workflow run ci.yml` that `Build, lint, test` moves
  past `Checkout`). Include the cost-per-PR estimate so the cap
  is set above the rolling burn rate plus headroom.
- M03.P0.T3 - Pre-name the third-party rebuilder per D13.
  Recommendation per research: a single named individual outside
  the chio core team but inside Backbay (platform team that owns
  `platform/CLAUDE.md` is the reasonable pick). Backup rebuilder
  named in the audit doc. If M08 lands NCC Group / Trail of Bits,
  fold the rebuild into their engagement scope.
- M03.P0.T4 - Document the reproducibility scope carve-out
  explicitly in `.planning/trajectory-3/audits/M03-ci-restoration.md`:
  Linux x86_64 yes; macOS / Windows known non-deterministic and
  out of scope for v3.18.

### P1 - Hosted CI workflows re-enabled + spending cap pinned

P1 is the single highest-leverage ticket in the trajectory; every
downstream milestone depends on it.

- M03.P1.T1 - Confirm billing restored. Push a no-op probe branch
  and run `gh workflow run ci.yml` (or wait for the push to fire
  the same workflow). Verify each required check moves past
  `Checkout`. Record the run URLs in the audit doc. This ticket
  is operational, not code; the gate-check is "the audit doc
  carries six green required-check run URLs".
- M03.P1.T2 - Pin the spending cap. Cap floor = rolling burn rate
  observed across one week of restored CI plus 50% headroom; cap
  alert at 80%. Document in `docs/runbooks/ci-billing.md`.
- M03.P1.T3 - macOS coverage trim (open question from research).
  PR-tier `Build, lint, test` runs ubuntu-latest only; release-
  binaries.yml and the conformance-matrix lane carry the macos-14
  / macos-15-intel coverage. Saves 10x/min at PR tier. Verified
  with one PR-tier run that exits without macOS-targeted test
  failures.
- M03.P1.T4 - Cycle through all 41 workflow files; for each one
  not on the required-checks list, confirm at least one green run
  on `main`. Workflows that are gated on a tag push or schedule
  are stamped "deferred to next tag" or "deferred to next
  schedule" with the trigger noted. Audit doc records the matrix.

### P2 - Admin-merge bypass scope inventory + silent regression triage

P2 takes the 118 PRs in #306-#425 and answers the one question
that matters: which of them would have failed CI on a working
runner? Approach: re-run CI on `main` HEAD first; if green, the
118 are merge-clean by accident. If red, bisect via
`workflow_dispatch` with explicit ref against the 118 merge
commits in binary-search order, with the `m{nn}-freeze-guard`
sentinels run first as a quick screen.

- M03.P2.T1 - Author `scripts/bisect-bypass.sh` that iterates the
  118 PR SHAs, dispatches `workflow_dispatch` against each, and
  collects the run IDs into a CSV under `.planning/trajectory-3/
  audits/M03-bypass-bisect.csv`. Idempotent; safe to re-run.
- M03.P2.T2 - Run the script. Cost ceiling: ~$50 if all pass
  quickly, several hundred if many timeout. Document the actual
  cost in the audit doc. Output: a triage matrix (`pass | fail`
  per PR; per-fail, the failing required check; per-fail, the
  owning milestone).
- M03.P2.T3 - Per-failure escalation. Each surfaced regression
  becomes a ticket on the owning milestone (M04 / M05 / M06 /
  M07 etc.). Per the M03 milestone budget, M03 itself triages
  rather than fixes. Escalation cap is 5; above 5, halt-trigger
  fires (canonical cadence trigger "regression cascade exceeds
  budget").
- M03.P2.T4 - First-flight protection. Land a one-line CI guard
  that flags admin-override merges on the next push so the
  bypass condition is harder to silently re-enter.

### P3 - Reproducible-build pipeline scaffold (Linux x86_64)

P3 lands the reproducible-build workflow plus the determinism
dampeners.

- M03.P3.T1 - Pin `[profile.release]` in workspace `Cargo.toml`:
  `codegen-units = 1`, `lto = "fat"`, `strip = "symbols"`. Verify
  no regression in the existing release-binaries lane (a green
  run on a probe tag passes through cosign and syft).
- M03.P3.T2 - Land `rust-toolchain.toml` at workspace root pinning
  the channel to an exact version (`1.85.0` for v3.18). Update
  `ci.yml` to honour the toolchain file (today `ci.yml` runs
  `rustup toolchain install stable`; the toolchain file is
  authoritative once committed). Verify locally that the
  workspace still builds against the pin.
- M03.P3.T3 - Author `.github/workflows/reproducible-build.yml`.
  Trigger: same `v*.*.*` tag push as `release-binaries.yml`,
  plus `workflow_dispatch`. Two parallel jobs `builder-a` and
  `builder-b` on independent ubuntu-24.04 runner instances.
  Both consume `SOURCE_DATE_EPOCH` derived from
  `git log -1 --format=%ct refs/tags/${tag}`. Both run
  `cargo build --release -p chio-cli`. Each emits a sha256 of
  every produced binary into `repro-${target}-${runner_id}.txt`.
- M03.P3.T4 - Author the `reproducibility-gate` job that runs
  `needs: [builder-a, builder-b]`, downloads both artifacts,
  diffs them, and fails the workflow on any sha256 mismatch.
  Mismatch surface logs the per-binary digest pair so a follow-on
  ticket can investigate.
- M03.P3.T5 - Author `scripts/rebuild-from-source.sh` that
  reproduces the same build outside hosted CI. Reads
  `rust-toolchain.toml`, sets `SOURCE_DATE_EPOCH` from the tag
  commit, and runs `cargo build --release -p chio-cli`. The
  third-party rebuilder runs this on their own machine in P5.

### P4 - SLSA L3 attestation end-to-end + public checksum index

P4 verifies the SLSA L3 generator runs end-to-end (it has never
been exercised against a real tag because billing has been
failing), and lands the public checksum index that M08 / M09
reviewers cite.

- M03.P4.T1 - Verify `slsa.yml` end-to-end against a probe tag
  (`v0.0.0-m03-probe`). Confirms the generator emits
  `chio-<source_sha>.intoto.jsonl`, uploads it to the release
  tag, and pushes a Rekor entry. Audit doc records the Rekor
  UUID. Soft-dep on M09 (SLSA workflow ownership).
- M03.P4.T2 - Extend `release-binaries.yml` to write
  `supply-chain/checksums/v<tag>.txt` after the matrix completes.
  Format: one line per artifact, `<sha256>  <filename>`. PR
  opens automatically against `main` titled
  `chore(release): publish v<tag> checksum index`.
- M03.P4.T3 - cosign-sign the checksum file. Output:
  `supply-chain/checksums/v<tag>.txt.sig` and
  `supply-chain/checksums/v<tag>.txt.pem` alongside the txt.
- M03.P4.T4 - Cite the Rekor UUID inside `v<tag>.txt` as a
  comment header so the in-repo index is the *index* and Rekor is
  the *witness*. Tampering with the index without also re-Rekoring
  is detectable.
- M03.P4.T5 - Document the checksum-index location in
  `docs/release-evidence.md`: where reviewers fetch it, what they
  verify, the Rekor witness URL pattern.

### P5 - Third-party rebuild reproduction + v3.18 retroactive certification

P5 closes the milestone. The third-party rebuilder named in P0
runs `scripts/rebuild-from-source.sh` against the v3.18 tag,
sends back hashes, and the audit doc records identity, hashes,
and date. Hosted CI is then re-run on the v3.18 release commit
to cement the retroactive cert.

- M03.P5.T1 - Re-run hosted CI on the v3.18 release SHA. Record
  the run URL in the audit doc closure attestation. (The v3.18
  release SHA is an open question from research; lock it in P0.T1
  before P5 starts.)
- M03.P5.T2 - Third-party rebuilder runs
  `scripts/rebuild-from-source.sh` against v3.18 on their own
  machine. They send back the sha256 of every produced binary
  plus a signed message (signed email or signed git commit)
  attesting authorship.
- M03.P5.T2.a - 0.25-day "external rebuild evidence received"
  audit-doc fill ticket. Records identity, matched hashes, date,
  audit-trail linkage. Vendor-evidence-shaped: short, paperwork.
- M03.P5.T3 - Audit doc closure attestations filled (section 4
  of `M03-ci-restoration.md`): hosted CI run URL,
  reproducible-build hash, SLSA provenance file URL, third-party
  rebuilder identity, matched hash, date.

## Cross-milestone interactions

Hard deps on trajectory-3 artifacts (express via `depends_on` in
the per-phase YAML):

- M03.P0.T1 (audit doc baseline) is the wave-opener for
  everything below in M03.

Forward references (other trajectory-3 milestones consuming M03):

- M02 (AI Lab beachhead) consumes hosted CI for the verdict-matrix
  and conformance-matrix workflows; both fail today because of
  billing. M02.P1 cannot start until M03.P1.T1 closes.
- M04 (mutation gate flip) cannot flip the gate while CI is
  bypassed. `mutants.yml` `mutants-nightly` job needs hosted CI;
  M04 reads `releases.toml.observed_consecutive_nightly_successes`
  which only ratchets on green nightlies. M04 starts after
  M03.P1.T1; the nightly run cadence becomes meaningful after
  M03.P1.T4.
- M05 (threat-coverage closure) requires
  `threat-model-coverage.yml` (one of today's failing workflows)
  to run green on `main` before the coverage gate can flip.
- M06 (cargo-vet / SBOM) consumes the `cargo-vet` and `cargo-deny`
  jobs in `ci.yml` as required checks. Both fail today.
- M08 (vendor evidence) cites M03 reproducible-build hash and the
  SLSA L3 attestation in the RELEASE_AUDIT memo. Needs P4 closed
  before vendor handoff.
- M09 (HITRUST i1) assessor scope is v3.18 + Opus and expects CI
  evidence. The SLSA provenance and reproducible-build hash from
  M03 are the load-bearing artifacts.
- M10 (Bedrock MCP marketplace) reviewer expects a green hosted
  CI signal on the release commit. P5 closure is the artifact.

Customer-facing reference:

- M01 (Opus production deployment) relies on hosted CI to be
  green for any production-cut artifact. M01 production cut
  blocked on M03.P5.

Cross-trajectory references (express in `soft_deps` as string
sentences):

- "trajectory-2 shipped `release-binaries.yml`, `slsa.yml`, and
  the cosign / syft signing infrastructure; M03 reuses them
  without forking the lane."
- "trajectory-2 shipped the `slsa-github-generator` reusable
  workflow pin at SHA `f7dd8c54...`; M03 verifies it end-to-end
  against a real tag for the first time."
- "trajectory-2 PR #287-#298 (kernel async migration) is the
  highest-risk surface for bypass-hidden regressions per the
  research bisect plan; M03.P2.T2 prioritises bisect on those
  SHAs."

## Risks and mitigations

1. **Billing reconciliation slips.** The billing-account owner may
   not be available to top-up promptly. Bypass mode persists
   beyond the M03 budget. Mitigation: surface in the canonical
   halt-trigger list per the autonomous-cadence memory entry
   ("billing reconciliation pending operator input"). Pre-write
   the one-pager so the owner can act in under 10 minutes.
   `docs/runbooks/ci-billing.md` is exactly that one-pager.
2. **Bypass bisect surfaces real regressions.** With 118 PRs in
   bypass mode, probability of at least one real regression is
   high. The trajectory-2 kernel async migration alone is the
   kind of change local `cargo test` passes while a CI `loom`
   model would catch. Mitigation: budget 0.5 day per surfaced
   failure; escalation cap 5; triage rather than fix in M03;
   surface to owning milestone. `M03.P2.T3` enforces this
   explicitly.
3. **Reproducible-build fails on platform-dependent build.rs.**
   `prost-build`, `tonic-build`, codegen for the verdict matrix
   bake `OUT_DIR` paths into the binary. Mitigation: scope
   reproducible-build to `cargo build --release -p chio-cli` only
   for v3.18; widen scope post-M03; track per-binary deltas in
   the audit doc.
4. **Hosted-runner cost surprise.** Even with billing restored, a
   run rate of $30-$50/day adds up. Mitigation: pin the spending
   cap (P1.T2) above rolling burn plus 50% headroom; alert at 80%;
   trim macOS coverage at PR tier (P1.T3).
5. **SLSA generator pin drift.** The `slsa-github-generator` SHA
   pin (`f7dd8c54...`) carries security-advisory exposure.
   Mitigation: subscribe to security advisories on
   `slsa-framework/slsa-github-generator`; M09 owner reviews
   pin updates per the OWNERS lane.
6. **Third-party rebuilder backs out.** Single-point-of-failure
   on the named individual. Mitigation: P0.T3 names a backup
   rebuilder. If M08 vendor engagement (NCC Group / Trail of
   Bits) lands, fold the rebuild into their scope as
   higher-weight evidence.
7. **Public checksum index tampering.** If the index lives in the
   repo and the same write surface is compromised, the index is
   compromised too. Mitigation: cosign-sign the index (P4.T3);
   cite the Rekor UUID (P4.T4); reviewers cross-check the index
   against Rekor.
8. **macOS / Windows reproducibility expectations.** Reviewers
   may read "reproducible build" as "every target byte-identical".
   Mitigation: P0.T4 documents the carve-out explicitly in the
   audit doc and the milestone narrative; v3.18 promises Linux
   x86_64 only; macOS / Windows have known non-determinism
   (codesign timestamps, PE COFF timestamps) called out
   ahead of reviewer engagement.

## Success criteria

A green light on M03 means all of the following are true:

- Hosted CI billing restored. Six required-check job names
  (`Build, lint, test`, `MSRV build and test`,
  `cargo-vet (supply-chain audit)`,
  `cargo-deny (supply-chain bans/advisories/licenses)`,
  `freeze-guard`, `bench-regression`) report green on `main` on
  consecutive consecutive runs across a 24-hour window.
- A pinned spending cap is in place on the GitHub billing
  account; cap value is documented in
  `docs/runbooks/ci-billing.md`.
- `.planning/trajectory-3/audits/M03-ci-restoration.md` records:
  bypass start (2026-04-26T23:00Z), days-since (numeric), 118
  PRs in #306-#425, the bisect triage matrix (per-PR pass/fail,
  per-fail owning-milestone), and any cross-milestone tickets
  opened as a result.
- `.github/workflows/reproducible-build.yml` exists, runs on
  `v*.*.*` tag push, executes two parallel ubuntu-24.04 builds
  with `SOURCE_DATE_EPOCH` from the tag commit, and passes the
  hash-compare gate on the v3.18 tag.
- `rust-toolchain.toml` is committed at workspace root pinning
  the channel to an exact version. `[profile.release]` block
  is committed in workspace `Cargo.toml` pinning
  `codegen-units = 1`, `lto = "fat"`, `strip = "symbols"`.
- `supply-chain/checksums/v3.18.txt` exists, carries one line
  per release artifact, is cosign-signed (`*.sig` and `*.pem`
  alongside), and cites the Rekor UUID emitted by the SLSA L3
  generator as a comment header.
- `slsa.yml` has run end-to-end against the v3.18 tag and
  produced `chio-<source_sha>.intoto.jsonl` attached to the
  GitHub Release.
- `scripts/rebuild-from-source.sh` exists, is documented in
  `docs/release-evidence.md`, and reproduces the v3.18 Linux
  x86_64 binary hash on a non-CI machine.
- The named third-party rebuilder has run the script against
  v3.18, sent back hashes that match the published index, and
  signed an authorship attestation. Audit-doc section 3 records
  identity, matched hashes, date, and audit-trail linkage.
- v3.18 release commit hosted-CI run URL, reproducible-build
  hash, and SLSA L3 provenance file URL are recorded in
  audit-doc section 4 closure attestations.
