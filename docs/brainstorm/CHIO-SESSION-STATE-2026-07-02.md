# Chio session state - 2026-07-02

Founder landing page for the autonomous work session on branch
`chio/autonomous-commerce-brainstorm`. Read the decisions section (4) first;
everything above it is context. Nothing below is committed or staged.

## 1. Executive summary

Over ~90 minutes an autonomous loop ran 10 waves (review, fix, brainstorm,
research) against this branch. It produced ~33 uncommitted working-tree files
plus a defused time-bomb in a sibling worktree, and a token-strategy document
bundle. The single biggest correction: the remembered "72 pre-existing test
failures" figure is stale. The real workspace baseline on this branch was 21
failures, all environmental (missing `wasm32-unknown-unknown` rustup target +
missing componentize-py artifact), all in `chio-wasm-guards`. Wave 6 fixed all
21 (added the target, ported the go-style skip-if-absent pattern), so a fresh
`cargo test -p chio-wasm-guards` is now green. The M1-12 e2e wall-clock
time-bomb DID detonate on 2026-07-01 and is now defused, but the fix lives in
the `arc-m1-launch` worktree (branch `chio/m1-launch`), uncommitted, not in this
branch. Several fix waves ran the cargo gate green (wasm-guards, xtask verdict);
the doc/spec/token waves did not touch cargo. Look first at: the commit-grouping
(section 3), the four Connor-only decisions with dollar-cheap answers (section
4), and the fact that wave 10 (egress + verifier fail-closed fixes) is still
running and PENDING. No code was changed by this synthesis pass.

## 2. Done and verified

| Wave | What shipped | Verification |
| --- | --- | --- |
| 1 | Test triage (baseline 21 not 72), branch review, M1-12 time-bomb located, token brainstorm (5 mechanisms) | Read-only; full `cargo test --workspace` run (9761 pass / 21 fail) |
| 2 | ARC->Chio rename audit, spec-conformance drift (7 items), SDK health | Read-only. (Security agent returned junk `test/a/b`; re-run in wave 4) |
| 3 | Token landscape research, Hyperliquid mechanism study, 7 product concepts | Read-only research (web) |
| 4 | Doc hygiene applied (14 files), 5 spec amendments drafted, A2A decision, security re-run (legit), SDK hygiene | Edits only; no cargo (shared-checkout lock) |
| 5 | Landscape memo written, m2-build merge audit, Kite/Virtuals teardown, x402 facilitator spike | Read-only + 1 new doc |
| 6 | wasm-guards 21 failures FIXED; launch-acceptance verdict derivation; M1-12 defused | `cargo test -p chio-wasm-guards` green, `-p xtask` green, clippy + fmt clean |
| 7 | Verifier-core review rev2 (4 suspicious findings), token invariants doc, counsel packet | rev1 (swarm+passport) FAILED (StructuredOutput retry cap) - re-run in wave 10 |
| 8 | A2A v1.0.0 restored (6 files + lint), @expo/config-plugins bump (clears xmldom highs) | Lint test green; mobile tsc build + audit 0 high; no cargo |
| 9 | anti-JELLY ADR-0015, latent time-bomb sweep, points-program spec | Read-only + 2 docs (points doc written despite junk structured-output) |

M1-12 time-bomb: the e2e test `e2e_pass_issue_charge_rollover_dormant_gates_2_and_5`
pinned Chio Pass capabilities to the June-2026 attestation window; the capability
`expires_at` hit `2026-07-01T00:00:00Z` and the kernel's wall-clock charge began
denying with `CapabilityExpired`. Defused in `arc-m1-launch` by deriving windows
from the real clock (the `current_month_window()` precedent). ONLY
`chio_pass_handlers.rs` was edited there (+49/-21). It is UNCOMMITTED and on a
DIFFERENT branch; the other 3 modified files in that worktree (escrow.rs,
revocation_store.rs, cli/pass.rs) are pre-existing WIP, not part of the fix. The
same fix still needs hand-porting to `chio/m2-build` (that copy has unrelated WIP
in the same file).

## 3. Working-tree inventory (grouped by intent)

Real `git status`: 26 modified + 7 untracked = 33 files. Proposed commit groups:

1. Rename / doc hygiene (waves 2+4): `.github/workflows/README.md`,
   `audits/evidence/mutants/chio-weights/README.md`,
   `audits/mutation/per-crate-configs/chio-weights.toml`,
   `crates/economy/chio-underwriting/src/marketplace_limits.rs`,
   `crates/observability/chio-lineage/src/anchor.rs`,
   `crates/products/chio-cli/tests/market_demo.rs`,
   `crates/trust/chio-reputation/src/tier.rs`,
   `crates/trust/chio-weights/Cargo.toml`, `crates/trust/chio-weights/src/lib.rs`,
   `docs/research/{CHIO_ANCHOR_RESEARCH,CHIO_SETTLE_PROTOCOL_DECISIONS,CHIO_SETTLE_RESEARCH,CHIO_WEB3_TRUST_BOUNDARY_DECISIONS}.md`,
   and the index parts of `docs/README.md`.
   `docs: complete ARC->Chio rename hygiene (CLI refs, research banners, index)`

2. Spec amendments (wave 4): `spec/PROTOCOL.md` (8.4 egress inventory, new 8.5
   Proof Room, 9 settlement proof-bundle/independent-chain, 6.3.2 swarm
   depth/fanout + root-only, 6 WYSIWYS signing invariant).
   `docs(spec): close conformance-audit drift (five amendments)`

3. A2A v1.0.0 restoration (wave 8): `docs/reference/A2A_ADAPTER_GUIDE.md`,
   `docs/superpowers/research/chio-launch/indices/external-standards-source-log.md`,
   `scripts/check-chio-proof-room-release-truth.sh`,
   `scripts/tests/check-chio-proof-room-release-truth.test.sh`, plus 2 lines in
   `spec/PROTOCOL.md` and 1 line in `docs/README.md`.
   `fix: restore A2A v1.0.0 truth in spec/docs/lint`

   NOTE: `spec/PROTOCOL.md` and `docs/README.md` each carry BOTH their group-2/1
   intent AND the A2A edit. Split with `git add -p`, or fold A2A into those two
   commits and keep the scripts/guide as a third. Your call.

4. SDK hygiene (waves 4+8): `sdks/typescript/.gitignore` (build-output ignores),
   `sdks/typescript/packages/mobile/package.json` (@expo/config-plugins
   ^7.8.4 -> ~56.0.10).
   `chore(sdk): ignore build outputs + bump expo plugins to clear xmldom highs`

5. wasm-guards test fix (wave 6): `crates/guards/chio-wasm-guards/tests/py_guard_integration.rs`,
   `crates/guards/chio-wasm-guards/tests/support/wasm_examples.rs`, `AGENTS.md`.
   `test(wasm-guards): skip-if-absent py guard, wasm32 preflight, toolchain docs`

6. Launch-acceptance verdict derivation (wave 6): `xtask/src/launch_acceptance.rs`,
   `scripts/tests/check-chio-proof-room-launch-acceptance.test.sh`.
   `fix(xtask): derive launch-acceptance verdict fail-closed`

7. New brainstorm/token docs (waves 5+7+9): all under `docs/brainstorm/` -
   `CHIO-TOKEN-EXTERNAL-LANDSCAPE-2026-07.md` (339 lines, 71 URLs),
   `CHIO-TOKEN-INVARIANTS.md` (13 invariants), `CHIO-TOKEN-COUNSEL-PACKET.md`
   (5 TOK-GATE-* gates), `CHIO-POINTS-PROGRAM-SPEC.md`, plus
   `docs/adr/ADR-0015-anti-jelly-escrow-circuit-breakers.md`. All untracked.
   `docs(brainstorm): token strategy bundle + anti-JELLY ADR`
   (ADR-0015 also wants a 1-line add to `docs/adr/README.md`, not yet done.)

8. Untracked non-repo files (do NOT commit): `workflows/scripts/pr-round-review.js`
   (personal one-off targeting `chio/m2-build`, hardcoded home path) and
   `sdks/typescript/package-lock.json` (stale root lockfile no CI consumes).

## 4. Decisions waiting on Connor

1. Approve the commit grouping for the ~33 files (section 3).
   Rec: yes, 7 commits as grouped, `git add -p` the two shared files.
   Why: every change is safe prose/spec/test/dep hygiene; grouping keeps history
   legible and lets you drop any group you dislike.

2. Delete vs keep root `sdks/typescript/package-lock.json`.
   Rec: delete it, and add `package-lock=false` to `sdks/typescript/.npmrc`.
   Why: no CI consumes it (CI uses tracked `bun.lock` + per-package
   `conformance` lock); it is stale (fails `npm ci`) and poisons `npm audit`
   (21 findings vs the real 1). Gitignoring hides a poisoned file npm keeps
   reading. Also drop `workflows/` (personal script) via `.git/info/exclude`.

3. Merge `chio/m2-build` into this branch (economy code: netting, prepaid,
   x402 signing, EAS/Verax, vgrade).
   Rec: yes, on a fresh integration branch (`chio/m2-into-brainstorm`), merge
   m2-build INTO this one. Why: cheap - merge-tree dry-run predicts only 5
   content conflicts (proof-room/CLI/test/script, not economy files);
   contracts/ untouched both sides; this branch is the newer base. Two manual
   post-merge fixes: confirm the egress contract covers m2's new x402/anchor RPC
   paths, and regenerate `spec/schemas/MANIFEST.sha256` for the `ungrounded`
   enum change.

4. First public demo pick, and pre- vs post-merge.
   Rec: x402 "pay-per-call vending machine" (agent hits protected API, pays USDC
   on Base Sepolia via EIP-3009, gets result + Proof Room receipt chain); build
   it AFTER the m2 merge. Why: top wow-factor and monetizes the exact protocol
   thesis; act two (escrow-backed) and act three (swarm waterfall) reuse the same
   rails. Post-merge so it sits on the newest economy code (netting/prepaid).

5. CDP API keys vs keyless facilitator for the demo settlement.
   Rec: adapter-hybrid - CDP facilitator primary (needs `CDP_API_KEY_ID/SECRET`),
   `https://facilitator.x402.rs` keyless fallback (live-probed, exact on
   base-sepolia). Why: never blocks the demo on key provisioning; Chio
   re-verifies locally before/after either call. Do NOT reference
   `x402.org/facilitator` - it is dead.

6. Token sequencing and where the 5 strategy docs live.
   Rec: tokenless-at-launch stays live (every credible rail is tokenless/USDC);
   keep the token out of the payment path permanently. Decide whether to
   co-locate the 5 strategy docs with the plan/design/M0-spec/roadmap docs that
   already live on `chio/token-contracts-brainstorm`. Why: those companion docs
   are on that branch, not here, so the memo's cross-links only resolve if the
   docs are together. No engineering blocked either way.

7. A2A interop-lane follow-up: add A2A 1.0.x fixtures to `chio-agent-web-interop`?
   Rec: defer, low urgency. Why: that crate's 0.3.0 evidence-projection pin is a
   separate, internally-consistent lane (not the runtime adapter, which is
   correctly v1.0). Adding 1.0.x fixtures is a real follow-up but not blocking.

## 5. Still running + queued

- Wave 10 (PENDING, do not wait): egress hardening (pinned-DNS helper +
  streaming byte cap + 2 regression tests) chained with verifier fail-closed
  fixes (rev2 R3 weakened-deny in `chio-runtime-proof-parity`, R4 hardcoded
  verdict in `merge_source_family_verifier_reports`), plus the wave-7 rev1
  re-run split into two reviewers (swarm-authority + transaction-passport).
  Completing this closes verifier-core coverage and unblocks the PR-937
  pre-merge checklist. Results not yet landed; verify cargo green when they do.

Known future cargo work not yet done:
- Latent time-bomb fixture regeneration - Class A first (the ~11 Web3
  identity-binding certs, past-dated, safe only while validation stays
  structural; they detonate the instant a wall-clock check lands in
  `chio-web3/src/identity.rs:59`). Then Class B (~3000 June-2026 proof-room
  fixtures). Regenerate as now-relative / frozen-clock BEFORE any wall-clock
  expiry enforcement.
- ADR-0015 follow-ups A/B/C: constrain `ChioBondVault.impairBondDetailed`
  beneficiaries to an allowlist (A, highest value); constrain
  `LiabilityClaimAdjudicationArtifact.adjudicator` to a roster (B); watch the
  identity/price admin surfaces (C). All contract changes = M4-class work.
- `checkpoint_seq` test-stale fix on `chio/m1-launch`
  (`mock_chio_root_registry...roundtrip` asserts genesis seq 0; production emits
  1). Pre-existing, one-line, not clock-related.
- Egress + verifier fail-closed fixes land with wave 10 (above).

## 6. Known-good facts worth keeping

- Real test baseline on this branch: 9761 pass / 21 fail / 39 ignored; the 21
  were all environmental in `chio-wasm-guards` and are now fixed. "72" is dead.
- There is NO protocol fee leg anywhere in the current x402 flow (kernel
  `payment.rs` or `chio-settle payments.rs`). A rebate/fee mechanism is net-new.
- Deployment is Base-first: contract family, deployment templates, x402 adapter,
  and root registry all target Base (eip155:8453/84532). No Solana contract
  lane exists; Solana is an anchoring/memo secondary lane only.
- `facilitator.x402.rs` works keyless on Base Sepolia (exact scheme, live-probed
  2026-07-02); `x402.org/facilitator` is dead (302 to a Linux Foundation page).
- Contracts are already token-generic (`EscrowTerms`/`BondTerms` carry an
  `address token` field), so a future CHIO ERC-20 needs zero new immutable
  contracts.
- The A2A adapter is correctly v1.0 (v1.0.0 released 2026-03-12, v1.0.1
  2026-05-28); the branch's earlier v0.3.0 downgrade was the error, now reverted.
