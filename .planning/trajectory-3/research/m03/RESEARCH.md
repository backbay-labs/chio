# M03 Research: Hosted CI Truth + Reproducible Builds

Trajectory: trajectory-3
Milestone: M03
Wave: W1 (release-gate anchor: RELEASE_AUDIT)
Lens: single (release legibility)
Date: 2026-04-30 (research) - written before P0 audit baseline.

This document is the IMPLEMENT-phase input. Hard counts requested by the
audit doc (`.planning/trajectory-3/audits/M03-ci-restoration.md` section 2)
are pre-computed below where the data is unambiguous; the remaining
slots are flagged.

## GitHub Actions billing failure mode

Observation (gh CLI, this repo, 2026-05-02 01:30 UTC). Every workflow
run since 2026-04-26T23:00Z has aborted with the annotation:

> The job was not started because recent account payments have failed
> or your spending limit needs to be increased. Please check the
> 'Billing & plans' section in your settings.

That is the canonical hosted-Actions billing string. It appears on
every job in the run (Coverage, JVM build, MSRV, cargo-deny, cargo-vet,
Build/lint/test, kani-public-pr, formal-tla, ...) and surfaces as a
top-level FAILURE on the run, not as a per-job test failure. The jobs
never started. Run timing of 2-9 seconds confirms boot-time refusal
(no checkout, no toolchain install).

Failure mode reading.

- The string covers two distinct conditions: (a) failed credit-card
  charge on the billing account, and (b) per-account or per-repo
  spending limit reached. GitHub does not differentiate these in the
  UI annotation.
- Sample of the last 500 runs (gh run list --limit 500): 489 failure,
  10 cancelled, 1 success. The single success is a `m05-freeze-guard`
  job, which runs on `ubuntu-latest` but is so short that it presumably
  predated the cap or hit a free-tier quirk.
- Last green ubuntu-latest CI run on `main`: somewhere between
  2026-04-26T19:48Z (last `Chio C++ SDK` success) and 2026-04-26T23:00Z
  (first cluster of failures). The exact transition is the run in page
  60 of `actions/runs?per_page=100` at 2026-04-26T23:00:42Z (m05-freeze-
  guard failure followed by a wall of failures). Total billed period
  before failure: roughly 6,700 runs.
- Total workflow runs reported by the API: 6,865.

Unblocking step.

1. Owner of the GitHub billing account (org or user that owns the
   `bb-connor/arc` repo, currently a personal repo per the `gh` URL)
   logs in to https://github.com/settings/billing.
2. If the failure is a card decline: update the payment method, then
   re-run the failed runs. Failed runs do NOT auto-rerun once billing
   is restored; they must be re-triggered (push, dispatch, or
   `gh run rerun`).
3. If the failure is a spending limit: raise the cap. The default cap
   on a free-tier personal account is $0 of paid usage; the cap must
   be raised to allow Actions on private repos beyond the included
   minutes, or the repo must be made public (which removes Actions
   billing from the equation but is a separate decision).
4. Verify with one push (or one `gh workflow run ci.yml`) that the
   `Build, lint, test` job moves past "checkout" before declaring
   billing restored.

D13 already locks the runner choice (GitHub-hosted, ubuntu-24.04 +
macos-14). M03 does NOT touch the billing account itself; the
implementation phase records the unblocking step in the audit doc as
"operational, not code", in line with the milestone scope.

Open question: is the billing failure on a personal account or on a
GitHub Organization? The repo URL `github.com/bb-connor/arc` reads as
a personal account. If the trajectory-3 customer pilot (M01 Opus)
needs an org-owned repo for SOC2 reasons, that is a separate
trajectory and out of scope for M03. For M03, the answer is: restore
billing on whichever account currently owns the repo.

## Admin-merge bypass inventory and bisect plan

Inventory.

- PRs in the requested range (#306-#425): exactly 118 merged PRs.
  First merge: PR #306 at 2026-04-29T18:09:28Z. Last merge: PR #425
  at 2026-05-01T07:51:38Z.
- All 118 PRs in #306-#425 merged AFTER the billing failure of
  2026-04-26T23:00Z. None of them had a green hosted CI run on the
  merge commit.
- Spot-check of PR #425 (the last in the range): 28 status checks
  reported, breakdown 25 FAILURE, 1 CANCELLED, 1 SKIPPED, 1 SUCCESS
  (Cursor Bugbot). The 25 failures include the load-bearing checks
  the branch ruleset names as required:
  - "Build, lint, test"
  - "MSRV build and test"
  - "cargo-vet (supply-chain audit)"
  - "cargo-deny (supply-chain bans/advisories/licenses)"
  - "freeze-guard"
  - "bench-regression"
  - "formal-tla (apalache safety)"
  - "kani-public-pr (lanes.pr harnesses)"
  - "check-regression-tests"
  - "Coverage", "JVM build" (advisory but still red)
  - per-language replay-gate, arena-determinism, header-stamp, vectors-
    byte-stable, cross-lang-bytes
- If PR #425's profile is representative, 118 PRs landed with all
  required checks red. Every one of them is an admin-merge.

Distribution by milestone tag (best-effort title parse):

| Bucket | Count |
|--------|-------|
| Other / no tag | 43 |
| M07 | 9 |
| M05 | 8 |
| M09 | 8 |
| M01 | 7 |
| M04 | 7 |
| M08 | 7 |
| M03 | 7 |
| M10 | 7 |
| M06 | 6 |
| M02 | 5 |
| deslop | 3 |
| sweep | 1 |

Bisect plan (M03.P2).

The bisect goal is not "find a single bad commit" - the goal is to
identify which of the 118 PRs *would have* failed CI on a working
runner if it had been run. Approach:

1. Once billing is restored (M03.P1), run the `Build, lint, test`
   workflow on `main` HEAD. Either it passes (best case: all 118 PRs
   were locally-tested correctly and merge-clean) or it fails (we
   have a ledger of regressions to land).
2. If `main` HEAD CI is red, bisect by re-running CI on the merge
   commits in #306-#425 in binary-search order. `gh run` against
   historical commits via `workflow_dispatch` with a SHA input.
3. The `m{nn}-freeze-guard` workflows are short and low-cost: run
   them first as a quick sentinel.
4. Per the trajectory-2 PR titles, the highest-risk surface is the
   M05 kernel async migration (PRs #287-#298, before the range, but
   also #271 #277 etc.) and the M06 wasm-guards reload work (#278
   onwards). Both rewrote concurrency primitives; both are exactly
   the kind of change that local `cargo test` can pass while a CI
   `loom` model would catch.
5. Budget: trajectory-3 milestone doc fixes 1-2 days for bisect plus
   0.5 day per surfaced failure, with a 5-failure escalation cap.
   Given 118 PRs in bypass mode this cap is likely to bite. Plan to
   triage rather than fix every regression in M03; surface them to
   their owning milestones.

Bisect tooling.

- `gh run rerun --commit <sha>` is not a real flag; the supported
  approach is `workflow_dispatch` with explicit ref, or push a probe
  branch at the commit SHA and let `pull_request` fire CI.
- A small script in `scripts/bisect-bypass.sh` should iterate the
  118 PR SHAs and dispatch-trigger CI on each, collecting the run
  IDs. Approximate cost: 118 runs * roughly $0.20 ubuntu-latest
  + macos-14 minutes per "Build, lint, test" run = on order of $50
  if all pass quickly, several hundred if many run to timeout.

## Hosted runner cost / capacity analysis

Trajectory-2 burned a billing account dry across ~6,700 runs. The
implication: the workflow set is heavy. Runtime drivers:

- `Build, lint, test` (the main lane) installs Lean 4 (elan), Aeneas
  + Charon, Kani, Creusot, wasm-pack, cargo-ndk, chromium-driver, plus
  Rust + Node + Bun + Python + Go + Java. First-run install dominates
  walltime; cache hits reduce it.
- `coverage` job has `timeout-minutes: 180`. Three hours of ubuntu-
  latest is roughly $1.40 of paid Actions per run.
- `mutants.yml`, `cflite_pr.yml`, `cflite_batch.yml`, `nightly.yml`,
  `bench-regression.yml`, `m06-sustained-p99-nightly.yml` all add load.

Runner choices (D13 picks GitHub-hosted; this is the cost ground-
truthing).

| Option | Per-minute cost (Linux x64) | Per-minute cost (macOS) | Notes |
|--------|------------------------------|--------------------------|-------|
| GitHub-hosted (chosen by D13) | $0.008 | $0.08 | macos-14 is 10x linux. macos-15-intel = $0.08, M-series macos-14 = $0.08. |
| Self-hosted (own VM) | infra cost only | n/a (Apple-silicon CI servers expensive) | D13 rejects: ops cost during pilot. |
| BuildJet | $0.004 (4-vCPU) to $0.016 (16-vCPU) | not offered | Half the Linux cost; macOS still GitHub-hosted. |
| Namespace.so | similar to BuildJet on Linux | offers macos-arm64 at lower cost | Newer entrant; still GitHub Actions-compatible. |
| Depot | similar; built-in build cache | macos-arm64 available | Cache-as-a-service for Docker/Cargo. |
| RunsOn (AWS) | ~$0.003-$0.005 (custom) | n/a (Apple) | Brings your own AWS account; Linux only. |

Recommendation for M03 P1: keep GitHub-hosted (D13). The third-party
runner discussion is a trajectory-3 follow-up if Actions billing
turns out to be the bottleneck; M03 does not block on it. macOS
matrix should be trimmed: the `release-binaries.yml` workflow already
covers macos-14 and macos-15-intel for release artifacts; PR-level
CI can be ubuntu-latest only if the test surface does not actually
need macOS coverage. (Open question to the IMPLEMENT phase: which
tests in `Build, lint, test` require macOS? None I see in `ci.yml`.)

Per-run cost estimate after restoration.

- `Build, lint, test` cold cache: 30 min ubuntu-latest = $0.24.
- `Coverage`: up to 180 min = $1.44.
- `MSRV`: 15 min = $0.12.
- `cargo-vet`, `cargo-deny`: 10 min each = $0.16 combined.
- `formal-tla`, `kani-public-pr`: 30-45 min each = up to $0.72.

Per PR, full CI sweep: roughly $3-$5 paid Actions. At trajectory-3
cadence (10 PRs/day on a busy day): $30-$50/day. The bypass-period
billing-failure data suggests the original cap was set well above
this, but the implementation phase should pin it explicitly so the
account does not trip again.

## Reproducible-build readiness

State of build determinism today.

- `Cargo.lock` is checked in at workspace root and pinned (verified
  by `git ls-files | grep Cargo.lock`).
- `release-binaries.yml` already builds five targets:
  - `x86_64-unknown-linux-gnu` (ubuntu-latest)
  - `aarch64-unknown-linux-gnu` (cross-rs, ubuntu-latest, image
    digest pinned: `sha256:7f8308a8...`)
  - `x86_64-apple-darwin` (macos-15-intel)
  - `aarch64-apple-darwin` (macos-14)
  - `x86_64-pc-windows-msvc` (windows-latest)
- The workflow already emits `*.sha256` files and signs blobs with
  cosign (`*.sig`, `*.pem`), and uploads `release-metadata.json`
  with `release_tag`, `source_ref`, `source_sha`.
- syft is used in the release lane; archive checksum verification
  pinned (`066c25...` for linux, `223f5a...` for darwin-amd64,
  `bc5ad2...` for darwin-arm64). Good prior art.

Gaps.

- No standalone `reproducible-build.yml` workflow. Two-builder hash
  compare does not exist. Today's release lane runs once per matrix
  cell; nothing checks that a second invocation on a different runner
  (or a third-party rebuilder) yields the same digest.
- `RUSTFLAGS` is set with `-C link-arg=-Wl,--threads=1` for CI
  (`CHIO_CI_RUSTFLAGS`), which helps determinism, but `-C debuginfo=0`
  is set per-step rather than globally. A `[profile.release]` block in
  workspace `Cargo.toml` to pin `codegen-units = 1`, `lto = "fat"`,
  and `strip = "symbols"` would dampen non-determinism further.
- Build environment is implicitly Ubuntu's apt; Rust toolchain comes
  from `rustup toolchain install stable`. "Stable" floats. Pin the
  exact rustc version (e.g. `1.85.0`) for reproducible-build runs;
  PR-tier CI can stay on rolling stable.
- macOS and Windows targets are notoriously non-reproducible (codesign,
  resource forks, PE timestamp). Scope the M03 P3 reproducible-build
  workflow to Linux x86_64 first; expand to aarch64-linux next; treat
  macOS / Windows as known non-reproducible for v3.18 and document.
- `git-secrets` is not installed in any workflow I inspected (grep
  miss in `.github/workflows/`). The `cargo-vet` and `cargo-deny`
  jobs cover supply-chain audit and license/ban policy. `cargo-deny
  check sources` enforces registry/git allowlists.

Reproducible-build pipeline (M03.P3 design).

1. New workflow `reproducible-build.yml` that runs on tag push (same
   trigger as `release-binaries.yml`) but on a different ubuntu-24.04
   runner instance, with rustc pinned to the same exact version, and
   with `SOURCE_DATE_EPOCH` set from the tag's commit time.
2. After both runners finish, a third job (`reproducibility-gate`)
   downloads the release-binaries artifact and the reproducible-build
   artifact and compares sha256. Mismatch fails the workflow.
3. Pin the build environment via the existing `Dockerfile` (verify it
   exists; it does) so the rebuild path can be exercised by external
   parties without hosted Actions.

## SLSA provenance toolchain

Already present.

- `.github/workflows/slsa.yml` exists. Owned by M09. Triggered by
  `workflow_run` after `release-binaries.yml` completes successfully.
- Uses `slsa-framework/slsa-github-generator/.github/workflows/
  generator_generic_slsa3.yml@f7dd8c54...` (pinned by SHA).
- Emits `chio-<source_sha>.intoto.jsonl` and uploads to the release
  tag (`upload-tag-name: ${{ ... release_tag }}`).
- Validates `release_tag =~ ^v<semver>$`, `source_ref =
  refs/tags/${release_tag}`, `source_sha` is a 40-char SHA, and
  `source_sha == workflow_run.head_sha`.

The pipeline already targets SLSA Level 3 (the `_slsa3.yml` reusable
workflow). The release-gate text in `03-...md` says "SLSA-style
provenance"; the actual emitted attestation IS SLSA Level 3 because
slsa-github-generator runs in a separately-permissioned reusable
workflow. M03 implementation should:

1. Verify the slsa.yml workflow has been exercised end-to-end against
   a real tag (likely never, since billing has been failing). The
   first restored run on a real tag is the certification event.
2. Add `actions/attest-build-provenance` to the per-binary build job
   if M09 wants belt-and-suspenders attestation in addition to the
   reusable generator. Not required for SLSA L3.

Gap: the `chio-<sha>.intoto.jsonl` file lives on the GitHub Release
attachments. There is no public *index* (i.e. a list of "every chio
release and its attestation URL") aside from the GitHub releases page.
The public checksum index (next section) is the natural home for
that pointer.

## Public checksum index design

Requirements (from M03 milestone doc).

- Live somewhere external evidence reviewers can fetch without a
  GitHub login.
- Authentic: tampering with the index must be detectable.
- Cheap: one milestone of effort, not a SaaS deal.

Options.

| Option | Pros | Cons |
|--------|------|------|
| `supply-chain/checksums/v3.18.txt` in the repo | Trivial; git history is the audit trail; cosign-signable. | Only as authentic as the repo write surface. |
| GitHub Pages site | Public URL, no login. | Branch-write triggers a Pages deploy; same write surface as main. |
| Sigstore Rekor entry | Transparent log, externally verifiable. | Requires every release to push to Rekor; the SLSA L3 generator already does this implicitly. |
| Static S3 bucket | Independent of GitHub. | Adds an AWS bill; SOC2 implications. |

Recommendation: hybrid.

1. Store the canonical checksum manifest in
   `supply-chain/checksums/v<tag>.txt` (one line per artifact, sha256
   + filename). The milestone doc already names this path.
2. Commit a cosign signature alongside (`v<tag>.txt.sig`).
3. Sigstore Rekor is already populated indirectly by slsa.yml (the
   reusable generator publishes to Rekor); cite the Rekor UUID in the
   `.txt` file as the primary tamper-evidence path. Then the in-repo
   checksum file is the *index* and Rekor is the *witness*.
4. Optional: enable GitHub Pages on a `gh-pages` branch and publish
   the `supply-chain/` tree there too, so reviewers can curl-fetch
   without learning git. Low priority for v3.18.

## Third-party rebuild plan

D13 names the rebuilder as "an independent contributor or a sister
team running the rebuild and confirming hash match". Concretely the
choice depends on what third-party scope is needed:

- *Same trust boundary:* a Backbay employee on a different team
  (e.g. the platform team that owns `platform/CLAUDE.md`). Cheap;
  low audit weight.
- *External individual:* a known Rust ecosystem contributor with an
  existing reputation. Higher audit weight; needs scheduling.
- *Reproducible-builds.org-style independent rebuilder:* the public
  "reproducible builds" community. Highest audit weight; longest
  lead time; not realistic on the trajectory-3 schedule.

Recommendation for M03.P4: pick a single named individual outside the
chio core team but inside Backbay. The audit doc records identity +
matched hash + date. The 0.25-day "external rebuild evidence
received" ticket is the ledger entry. If M08 (independent crypto
review) lands on NCC Group / Trail of Bits, ask them to also rebuild
v3.18 from source as part of their existing engagement; that turns
M03's third-party rebuild into a higher-weight artifact "for free".

Mechanics.

1. Publish `Dockerfile` + the reproducible-build script as a single
   `scripts/rebuild-from-source.sh`. The third party runs it on
   their own machine.
2. They send back the sha256 of every produced binary plus a signed
   email or signed git commit attesting authorship. Audit doc
   stores both.
3. If hash mismatches: M03 fails; investigate non-determinism and
   either fix or document. Common culprits: build timestamps,
   `OUT_DIR` paths, codegen-units randomness, `/tmp` paths in
   error messages baked into the binary.

## Per-phase research findings (P0-P5)

P0 - Audit baseline.

- Hard count: weeks since admin-merge bypass began. Bypass started
  2026-04-26T23:00Z; today is 2026-04-30. Roughly 4 days, not weeks
  yet. Audit doc field "weeks since admin-merge bypass began" should
  read 0 (less than one week) at P0 close.
- Hard count: CI workflow files currently disabled. Zero are
  *disabled at the YAML level* - all 41 workflows in `.github/
  workflows/` parse and trigger on push/PR. They fail at the runner-
  start gate because of billing, not because the file is commented
  out. The audit-doc question's wording is a holdover from a
  workflow-disable bypass scheme; the actual bypass is account-level.
  Audit-doc answer: 0 disabled, but all 41 are non-functional due
  to billing.
- Hard count: failing tests at the last green hosted-CI run before
  bypass. The last green CI on main was 2026-04-26T19:48Z. Reading
  the test count out of that run requires `gh run view <id>
  --log-failed` once billing is restored (the older logs are still
  fetchable but the run conclusion was failure). Defer to IMPLEMENT
  P0.

P1 - Hosted CI workflows re-enabled.

- Step 1: confirm billing restored.
- Step 2: push a no-op probe branch and run `gh workflow run ci.yml`
  + verify each required check turns green. Likely it will not -
  some of the required checks were already breaking before billing
  failed (the trajectory-2 PR catalog mentions "fix wasm-guards loom
  model deps" and similar landings).
- Step 3: ratchet from advisory to required only after the corresponding
  check has been green on main for at least 24 hours.

P2 - Reproducible-build pipeline scaffold.

- Linux x86_64 only for v3.18.
- Pin rustc by version, not by channel.
- `SOURCE_DATE_EPOCH` from tag commit time.
- Two-builder hash compare in a single workflow with two parallel
  jobs.

P3 - SLSA + checksum publication.

- slsa.yml already wired for SLSA L3.
- New: `supply-chain/checksums/v<tag>.txt` committed automatically
  by `release-binaries.yml` after build.
- New: cosign signature on the checksum file.

P4 - External third-party rebuild.

- Name the rebuilder before P3 starts; lead time matters.
- Audit-doc fields: identity, matched hash, date, audit-trail link.

P5 - v3.18 retroactively certified.

- Re-run hosted CI on the v3.18 release commit (whatever SHA the
  trajectory-2 release tagged). Greens fill the audit doc closure
  fields.

## Cross-milestone unblocking dependencies

| Downstream | Why it depends on M03 | Specific artifact |
|------------|------------------------|-------------------|
| M02 (AI Lab beachhead) | Partner-facing CI artifacts (verdict matrix, conformance) | `verdict-matrix.yml` and `conformance-matrix.yml` need real runner. |
| M04 (mutation gate flip) | The blocking gate cannot flip while CI is bypassed | `mutants.yml` `mutants-nightly` job needs hosted CI. |
| M05 (threat-coverage closure) | `threat-model-coverage.yml` is one of today's failing workflows | Coverage gate flip requires green run on `main`. |
| M06 (cargo-vet / SBOM) | `cargo-vet` job in `ci.yml` is required-check | M06 ships supply-chain audits that require this lane to be working. |
| M08 (vendor evidence) | Reviewer cites CI artifacts in RELEASE_AUDIT memo | Hosted CI green run + reproducible-build hash. |
| M09 (HITRUST i1) | Assessor scope is v3.18 + Opus, expects CI evidence | SLSA provenance + reproducible-build hash. |
| M10 (Bedrock MCP conformance) | Bedrock marketplace reviewer expects CI signal | Hosted CI green on release commit. |

Net: M03 unblocks every other trajectory-3 milestone. P1 (billing
restored + workflows re-enabled) is the single highest-leverage
ticket in the trajectory.

## Risk register

1. **Billing reconciliation slips.** The billing account owner may
   not be available to top-up promptly. Mitigation: surface this in
   the AUTONOMOUS-PROMPT canonical-trigger list (this is one of the
   eleven valid halt conditions). Pre-write a one-pager the owner
   can act on.
2. **Bypass bisect surfaces real regressions.** With 118 PRs in
   bypass mode, the probability of at least one real regression is
   very high (the M05 kernel async migration alone is high-risk).
   Mitigation: budget 0.5 day per failure, escalate to user at >5.
   Triage rather than fix in M03; refer the regression to the owning
   milestone.
3. **Reproducible-build fails on platform-dependent deps.** The
   workspace pulls Lean 4, Aeneas, Charon, Kani, Creusot via tarball.
   These are not part of the binary distribution but are part of the
   *test* path. Build-time deps (build.rs) include `prost-build`,
   `tonic-build`, codegen for verdict matrix. Mitigation: scope
   reproducible-build to `cargo build --release -p chio-cli` for
   v3.18; widen scope post-M03.
4. **Hosted-runner cost surprise.** Even with billing restored, a
   run-rate of $30-$50/day adds up. Mitigation: set a monthly
   spending cap; alert at 80%; trim macOS coverage at PR tier.
5. **SLSA generator pin drift.** The `slsa-github-generator` SHA
   pin is `f7dd8c54...`. SLSA major-version bumps may require a
   pin update; we should subscribe to security advisories on that
   repo.
6. **Third-party rebuilder backs out.** Single-point-of-failure on
   the chosen individual. Mitigation: name a backup rebuilder. If
   M08 (NCC Group / Trail of Bits) lands, fold the rebuild into
   their engagement scope.
7. **Public checksum index tampering.** If the index lives in the
   repo and the same write surface is compromised, the index is
   compromised too. Mitigation: cosign-sign the index; cite Rekor
   UUID; periodically diff against Rekor.
8. **macOS/Windows reproducibility expectations.** Reviewers may
   read "reproducible build" as "every target is byte-identical".
   Document that v3.18 promises Linux x86_64 reproducibility only,
   and that macOS / Windows have known non-determinism (codesign
   timestamps, PE COFF timestamps) that are out of scope.

## Recommended ticket scaffold

P0 (audit baseline + billing-restoration plan):

- M03.P0.T1: Open `audits/M03-ci-restoration.md` with hard counts
  filled (4 days since bypass; 0 workflows YAML-disabled but 41
  account-blocked; failing-test count deferred to P1).
- M03.P0.T2: Document the billing-restoration runbook (this
  research doc's "Unblocking step" section, formalized in
  `docs/runbooks/ci-billing.md`).
- M03.P0.T3: Pre-name the third-party rebuilder per D13. Send the
  ask early; lead time is the bottleneck for P4.

P1 (hosted CI re-enabled + bypass bisect):

- M03.P1.T1: Confirm billing restored; one push to probe.
- M03.P1.T2: Establish pinned spending cap on the GitHub billing
  account.
- M03.P1.T3: Bisect script `scripts/bisect-bypass.sh` plus invocation
  log under `.planning/trajectory-3/audits/M03-ci-restoration.md`
  (section 2 hard-count fill).
- M03.P1.T4: Per-failure escalation tickets (open as discovered;
  refer to owning milestone).

P2 (reproducible-build pipeline scaffold):

- M03.P2.T1: New `.github/workflows/reproducible-build.yml` (Linux
  x86_64 only).
- M03.P2.T2: Pin rustc version; set `SOURCE_DATE_EPOCH`; pin
  `[profile.release]`.
- M03.P2.T3: Two-builder hash compare gate.

P3 (SLSA + checksum index):

- M03.P3.T1: Verify `slsa.yml` end-to-end on a real tag.
- M03.P3.T2: New `supply-chain/checksums/v<tag>.txt` published by
  `release-binaries.yml`; cosign-signed.
- M03.P3.T3: Cite Rekor UUID in the checksum file.

P4 (third-party rebuild evidence):

- M03.P4.T1: Publish `scripts/rebuild-from-source.sh`.
- M03.P4.T2: External rebuild executed; matched hash recorded.
- M03.P4.T3 (0.25 day): "external rebuild evidence received" audit-
  doc fill.

P5 (v3.18 retroactive certification):

- M03.P5.T1: Re-run CI on v3.18 release SHA; record run URL.
- M03.P5.T2: Audit doc closure attestations filled.

## Open questions for IMPLEMENT phase

1. Who currently holds the GitHub billing account? Personal account
   `bb-connor` or an org? Is there a backup payer?
2. What is the actual v3.18 release commit SHA? (The trajectory-3
   docs reference "v3.18 + Opus deployment" but the tag is not
   visible in the repo's tag list yet; this should be fixed before
   P5.)
3. Does the `Build, lint, test` matrix actually need macOS coverage
   at PR tier? If not, drop it and save 10x/min.
4. Is the third-party rebuilder a Backbay employee, an external
   individual, or folded into M08 (NCC/ToB)? D13 says "third party"
   without specifying; lock the answer in P0.
5. Should the public checksum index live in `supply-chain/checksums/`
   only, or also be published to GitHub Pages? Latter doubles the
   surface; former is enough for SLSA L3.
6. The `releases.toml` `cycle_end_tag` is empty and
   `observed_consecutive_nightly_successes` is 0. This means the
   mutation gate is still advisory. M03 does NOT flip the gate
   (that's M04), but M03 does need the nightly mutants run to
   actually execute, which has been impossible during the bypass.
   Coordinate with M04 in the W1 wave.
7. macOS/Windows reproducibility scope: explicitly carved out for
   v3.18, or claimed and we discover at P3 that it's not feasible?
   Recommend explicit carve-out in the milestone doc and audit doc
   from P0.
