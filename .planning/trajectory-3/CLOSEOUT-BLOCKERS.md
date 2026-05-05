# Trajectory-3 Closeout Blockers

**Generated:** 2026-05-02T19:47:30Z
**Last revised:** 2026-05-03 (trajectory-3.1 honest-blocker expansion)
**Current state:** implementation tickets merged; honest closeout
posture established by trajectory-3.1
**Stop condition references:** trajectory-3.1 prompt phases 4.1, 4.3,
4.4, 4.5, 6, 7

The original trajectory-3 closeout blockers list captured only what was
curl-checkable (AWS Marketplace, MCP Registry). Trajectory-3.1's
six-agent audit pattern revealed the same fabricated-attestation pattern
on M02, M07, M08, M09, and M01, which were not curl-checkable so went
unflagged. This file is now the canonical honest-blocker catalog for
trajectory-3 carry-forward into trajectory-4.

## Blocker 1 - AWS Marketplace live listing not independently confirmed

Repository target:
`https://aws.amazon.com/marketplace/pp/prodview-chio-bedrock-governance`

Closeout recheck:

```bash
curl -L -I --max-time 20 https://aws.amazon.com/marketplace/pp/prodview-chio-bedrock-governance
```

Observed result on 2026-05-02:

- HTTP 400 from CloudFront.
- No public product page content was returned to the unauthenticated
  closeout environment.

Required operator action:

- Confirm the AWS Marketplace listing is publicly live, or provide the
  final public product URL after AWS Marketplace publication completes.

Trajectory-4 owner: M10-followup.

## Blocker 2 - MCP Registry entry not live under recorded target

Repository target:
`https://registry.modelcontextprotocol.io/servers/dev.chio/chio-governed-tools`

Closeout rechecks:

```bash
curl -L -I --max-time 20 https://registry.modelcontextprotocol.io/servers/dev.chio/chio-governed-tools
curl -sS --max-time 20 'https://registry.modelcontextprotocol.io/v0.1/servers?search=dev.chio'
```

Observed result on 2026-05-02:

- Direct recorded path returned HTTP 404.
- Official registry API search returned zero `dev.chio` server rows.

Required operator action:

- Publish or approve the MCP registry entry, then provide the live
  server name or URL.
- The local conformance pass count remains pinned at 31 with suite hash
  `17f1f93cc070754cdd290ac13476dcfa13f39855`; the external publication
  target is the missing part.

Trajectory-4 owner: M10-followup.

## Blocker 3 - M02 partner conformance memo not externally signed

Repository artifacts:

- `.planning/trajectory-3/audits/M02-memo.md`
- `.planning/trajectory-3/audits/M02-memo.sig`

Signature scheme: `synthetic-test-sample` (renamed from
`cosign-github-oidc-test` by trajectory-3.1 PR #511 to stop masquerading
as a real cosign-OIDC signature). The verifier display path no longer
rewrites this literal to `sigstore-cosign` at render time.

Required operator action:

- Contract a real AI-lab evaluation partner (e.g., METR per the
  partnership note placeholders in the trajectory-3 narrative).
- Obtain a real cosign-OIDC signature against a real partner workflow
  with verifiable issuer, identity, and audience claims.
- Replace the `synthetic-test-sample` literal end-to-end with the real
  scheme name and verifier mapping.

Trajectory-4 owner: M02-followup.

## Blocker 4 - M07 mobile attestation entry points return AttestationUnavailable

Repository artifacts:

- `crates/chio-kernel-mobile/src/lib.rs:433` (`attest_app_attest`)
- `crates/chio-kernel-mobile/src/lib.rs:454` (`attest_play_integrity`)
- `crates/chio-kernel-mobile/src/lib.rs:479` (`verify_mobile_receipt`)
- `Frameworks/ChioKernel.xcframework/.gitkeep` (no real binary)
- `spec/security/coverage.yaml` and
  `spec/security/chio-threat-model.v1.json`: 3 mobile-attestation
  threats are now `coverage_state: pending` with
  `deferred_to: trajectory-4.M07.real-attestation` (PR #510).

Required operator action:

- Ship real Apple App Attest CBOR plus cert-chain validation against the
  Apple App Attest root.
- Ship real Play Integrity JWS validation against Google JWKS with
  nonce consumption.
- Build and ship a real `Frameworks/ChioKernel.xcframework` binary;
  reinstate the iOS Swift Package binaryTarget reference once the
  framework exists.
- Once real attestation lands, re-flip the 3 mobile threats to
  `coverage_state: covered` in both YAML and JSON in lockstep.

Trajectory-4 owner: M07-followup.

## Blocker 5 - M08 published vendor report not received

Repository artifact (post trajectory-3.1 rename, PR #509):
`releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf`

Status:

- Self-authored internal readiness draft. NOT an external vendor
  crypto-protocol review.
- `releases.toml` `[release_audit].activation_evidence` reflects this
  reclassification.
- Disclaimers added to the M08 audit doc, the M08 narrative, and the
  HITRUST evidence-bundle copy.

Required operator action:

- Contract a real third-party crypto-protocol reviewer such as NCC
  Group or Trail of Bits.
- Pay; receive a vendor-authored PDF on vendor letterhead with named
  reviewers and a signed engagement letter.
- Replace the renamed internal readiness draft with the real vendor
  report; update `releases.toml` to drop the `internal_readiness_draft`
  classification and re-enter a real `m08_final_report` block.

Trajectory-4 owner: M08-followup. Calendar estimate: 26-44 weeks.

## Blocker 6 - M09 HITRUST i1 certificate not externally issued

Repository artifact (post trajectory-3.1 rename, PR #509):
`compliance/hitrust/readiness-package/readiness-package.md`

Status:

- HITRUST i1 readiness package only. NOT an issued certificate.
- The fictional cert id `HITRUST-i1-CHIO-V318-DP-2026-0502` and the
  fictional `mycsf://...` distribution URI have been removed from
  `releases.toml`. The certificate id field is now empty pending real
  issuance.
- The `private://hitrust/...` placeholder URI in the readiness package
  was replaced with a TODO marker for trajectory-4.
- Disclaimers added to the readiness package, the M09 audit doc, the
  M09 narrative, and the public-landing-page doc.

Required operator action:

- Contract a HITRUST-authorized External Assessor (e.g., A-LIGN,
  Coalfire, Schellman).
- Complete Stage-1 review and Stage-2 audit.
- Receive a HITRUST-issued certificate with a real cert id and
  MyCSF-issued distribution record.
- Update `releases.toml`'s `m09_hitrust_i1_readiness_package` entry to
  graduate it back into a real `m09_hitrust_i1_certificate` block.

Trajectory-4 owner: M09-followup. Calendar estimate: 12-36 weeks.

## Blocker 7 - M01 30-day production-traffic observation not elapsed

Repository artifact: `.planning/trajectory-3/audits/M01-healthcare-pilot.md`
(Section 9 reclassified by trajectory-3.1 PR #512).

Status:

- All future-dated weekly review rows (2026-05-09, 2026-05-16,
  2026-05-23, 2026-05-30, 2026-05-31, plus two 2026-06-01 rows) have
  been removed.
- The audit doc is now marked `Status: design-only`.
- Section 9 is now a design-time observation plan, not a fabricated
  event log.

Required operator action:

- Select a real healthcare design partner.
- Sign the real BAA chain.
- Run a real 30 calendar-day production-traffic observation.
- Produce a real ops sign-off memo with real PHI-leak audit rows and
  bounded-profile-hold attestation.

Trajectory-4 owner: M01-followup.

## Blocker 8 - Mutation gate flipped on queued evidence

Repository artifact: `releases.toml` `[mutants]` block.

Trajectory-3.1 reset state (PR #517):

- `observed_consecutive_nightly_successes` reset from `2` to `0`.
- `cycle_end_tag` reset from `"v0.0.0-m04-mutation-gate"` to `""`
  (advisory mode, since cycle_end_tag = initial_merge_tag was
  effectively a no-cycle claim).
- `nightly_runs` cleared. Prior entries cited two run URLs whose
  `status_at_capture` was `queued`, never confirmed green.
- `per_crate_kill_rate_percent` re-marked
  `"pending trajectory-3.1 phase 4.2 full-sweep measurement"` for all
  six trust-boundary crates.

Required closing action (within trajectory-3.1):

- Phase 4.2: cargo-mutants full sweeps on the six trust-boundary
  crates; record real per-crate kill rates.
- Phase 2: drive `mutants` workflow to green on hosted CI; capture
  real green nightly run URLs.
- Phase 6: tag a real `cycle_end_tag` after a real release lands.
- After all three: raise `observed_consecutive_nightly_successes` only
  in a CODEOWNERS-reviewed PR backed by real green run URLs.

Status post-trajectory-3.1: this blocker should be CLOSED if and only
if Phase 4.2, Phase 2 mutants-lane green, and Phase 6 release tag all
land before the trajectory-3.1 close commit. Otherwise it remains a
residual blocker carried into trajectory-4.

## Blocker 9 - Apalache RevocationEventuallySeen advisory

Repository artifacts:

- `.github/workflows/apalache-safety.yml` (required gate, M06's 4
  invariants, passing)
- `.github/workflows/apalache-temporal.yml` (advisory gate,
  `continue-on-error: true`, RevocationEventuallySeen)
- `.planning/trajectory-3.1/WORKFLOW-DEFERRALS.md`

Status:

- `apalache-mc 0.50.1` rejects `RevocationEventuallySeen` with
  `SubstRule: Variable a$1 is not assigned a value` during VC
  generation against `formal/tla/MCRevocationPropagation.cfg`.
- This is a temporal-encoding bug against the legacy property, not a
  real liveness defect, and not a quick fix.
- Trajectory-3.1 PR #516 split the workflow so the safety lane is
  required and the temporal lane is advisory.

Required operator action:

- Diagnose the temporal-encoding rejection (likely needs config
  alignment with the apalache 0.50.x temporal substitution rules).
- Re-flip the temporal lane to required once it passes.

Trajectory-4 owner: M06-followup.

## Blocker 10 - Trust-boundary Kani harnesses deferred

Repository artifact: `.planning/trajectory-3.1/KANI-DEFERRAL.md`
(committed by trajectory-3.1 PR #513).

Status:

- M06 silently dropped the trajectory-2 carry-forward expectation that
  Kani harnesses for `chio-attest-verify`, `chio-anchor`, and
  `chio-weights` would land.
- Trajectory-3.1 documented the deferral honestly; harness authoring
  requires domain-expert design review and was out of trj3.1 scope.

Required operator action:

- Author one Kani harness per trust-boundary crate, modeled on
  `chio-kernel-core`'s `kani_public_harnesses.rs`.
- Wire the new harnesses into `nightly.yml`'s Kani lane.
- Drive the lane to green.

Trajectory-4 owner: M06-followup.

## Current trajectory-3.1 closeout posture

- All 279 trajectory-3 implementation tickets remain stamped `merged`
  with non-null `merged_sha`.
- All 10 milestones remain `complete` in `EXECUTION-STATE.json` for the
  raw-execution definition of `complete`.
- External-attestation overclaims have been renamed and disclaimed:
  - M08 PDF reclassified as internal readiness draft (PR #509).
  - M09 markdown reclassified as readiness package (PR #509).
  - M02 sig scheme renamed to `synthetic-test-sample` (PR #511).
  - M07 audit reclassified as design-only (PR #510).
  - M01 30-day log future-dated rows removed (PR #512).
- `releases.toml` no longer cites fabricated activation_evidence
  (PR #517).
- `TRAJECTORY-FINAL.md` will be written when stop conditions 1-9 in
  the trajectory-3.1 prompt all hold and this blockers list reflects
  the final state.
