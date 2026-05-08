# Bar 1 baseline -- mutation kill banner + threat-evidence directory

**Bar**: 1 (Lane A: realize the floor).
**Baseline captured**: 2026-05-08.
**Baseline SHA**: `708c7bb33df43594f5e76542b05fca7a56d9689e`.
**Baseline branch**: `planning branch`.
**Authoritative source**: `README.md` workspace mutation banner + `audits/evidence/threats/*.json` files.

This file records the CURRENT (pre-release work) state of Bar 1 so the post-release work
delta is measurable against a fixed reference. The Bar 1 close criteria
are normative in `.planning/trajectory-5/debate/00-SYNTHESIS.md` Lane A
and `SHIP-BAR-TRACKER.md` Bar 1 row.

---

## Mutation banner (current, pre-release work)

From `README.md` line 17 (verbatim, captured 2026-05-08):

> "Mutation kill: 31% - six-crate trust-boundary mutation baseline,
>  mixed sweep/shard n=375 viable mutants - 2026-04-29"

| Field | Value |
|---|---|
| Workspace mutation kill (banner) | 31% |
| Banner measurement date | 2026-04-29 |
| Sample size | n=375 viable mutants |
| Crate scope | 6 trust-boundary crates (banner does not enumerate them) |
| Per-crate breakdown | BASELINE-GAP -- the banner does not publish per-crate numbers; per-crate breakdown is a mutation evidence item deliverable |

Per-crate breakdown gap: pre-release work there is no committed per-crate
mutation kill table. The synthesis target (Bar 1 close) requires a
per-crate breakdown. mutation evidence item (run baseline) and mutation evidence item (publish
per-crate numbers) are the W3-fix-log split that lands per-crate
numbers in Wave 1 of Lane A.

## Mutation evidence directory (current, pre-release work)

`ls audits/evidence/mutation/ -- not present`. The directory does NOT
exist at baseline. mutation evidence item creates it and writes
`audits/evidence/mutation/<crate>/<run-id>.json` per trust-boundary
crate. The summary file `audits/evidence/mutation/banner.json` is the
machine-readable signal for Bar 1 (per `SHIP-BAR-TRACKER.md`
"Machine-readable signal" row).

BASELINE-GAP: pre-release work, no `audits/evidence/mutation/banner.json` exists.

## Threat-evidence directory (current, pre-release work)

```
$ ls audits/evidence/threats/
agent_velocity_abuse.json          mobile_attestation_replay.json     ssrf_via_http_substrate.json
audience_confusion.json            native_channel_replay.json         tee_quote_forgery.json
behavioral_sequence_attack.json    passkey_credential_theft.json      tool_server_escape.json
capability_token_theft.json        pii_phi_exposure.json              wasm_guard_resource_exhaustion.json
cumulative_data_exfiltration.json  play_integrity_token_replay.json   weights_hash_spoof.json
delegation_chain_abuse.json        pq_signature_downgrade.json
device_key_extraction.json         resource_exhaustion_dos.json
kernel_impersonation.json          ssrf_via_http_substrate.json
```

Count: 20 files. Authoritative threat-row count is 20 (one row per
`spec/security/chio-threat-model.v1.json`); the synthesis text says
"21" but the on-disk count is 20 per W3 Lane A fix-log "R1 MAJOR
section 4.2 -- threat-count drift (21 vs 20)". All Lane A docs use 20
with footnote.

Each file (verified pre-release work by spot-check of
`audits/evidence/threats/agent_velocity_abuse.json`) is a placeholder:

```json
{
  "caught": 0,
  "needs_real_run": true,
  "note": "Bootstrap placeholder. Replace with real cargo-mutants evidence in trajectory-4 wave 4. Caught >= 1 promotes the row out of weak_coverage.",
  "ran_at": "1970-01-01T00:00:00Z",
  "survivors": []
}
```

Baseline tally:

| Field | Value |
|---|---|
| Threat-evidence files on disk | 20 |
| Files with `caught >= 1` | 0 |
| Files with non-1970 `ran_at` | 0 |
| Files with `needs_real_run: false` | 0 |
| Files with a `triage_status` field (Wave 1 deliverable) | 0 |

The 20/0/0 PASS banner is a placeholder per `SHIP-BAR-TRACKER.md`
Bar 1 "Current state" cell. `scripts/check-threat-coverage.sh` PASSes
today only because of the placeholder bootstrap.

## Target state (post-release work)

| Field | Target |
|---|---|
| Workspace mutation kill | >= 65% (observed, not target) |
| `chio-attest-verify` mutation kill | >= 80% |
| Per-crate breakdown | Published as `audits/evidence/mutation/<crate>/<run-id>.json` per trust-boundary crate, plus aggregate `audits/evidence/mutation/banner.json` |
| Threat-evidence: real `caught >= 1` | 19 of 20 (1 deferred to trj6 per Risk Register R3: `wasm_guard_resource_exhaustion`); Wave 1 triage may grow the deferral count if `IMPL-PARTIAL`/`BLOCKED-BY-ARCHITECTURE` rows surface |
| `ran_at` non-1970 | All non-deferred files |
| `needs_real_run` | `false` for all non-deferred files |
| `triage_status` field | Present on every file per W3 Lane A fix |

## Measurement command pattern (post-release work)

The canonical `cargo mutants` invocation Lane A uses (from
`lane-a-floor/mutation-budget.md` and planning docs mutation evidence item):

```
cargo mutants -p <crate> --no-shuffle --jobs <N> \
  --output audits/evidence/mutation/<crate>/<run-id>.json
```

Per-crate runs aggregate into the workspace banner. The
`scripts/banner.sh` helper (mutation evidence item ticket) updates
`README.md` line 17 from observed run output.

Trust-boundary crates (per `OWNERS.toml` `lanes.A.owner_globs`):
- `chio-attest-verify`
- `chio-anchor`
- `chio-weights`
- `chio-equivalence-tests` (path retained but TRJ4-019 deferred to trj6)
- `chio-kernel-core` (capability_verify)
- One additional crate to be confirmed during mutation exclusion audit exclusion-list audit

## Re-measurement protocol (release close)

The release work closeout wave runs:

1. Run `cargo mutants` per trust-boundary crate; emit JSON evidence
   under `audits/evidence/mutation/<crate>/<run-id>.json`.
2. Aggregate to `audits/evidence/mutation/banner.json`:
   `{ "kill_rate": "<observed>", "per_crate": [...], "observed":
   true, "ran_at": "<RFC3339>" }`.
3. `scripts/banner.sh` rewrites `README.md` line 17 from
   `audits/evidence/mutation/banner.json`.
4. `scripts/check-threat-coverage.sh` PASSes at 19/0/1 (or whatever the
   final triage tally is) with non-meta evidence; `ran_at` is non-1970
   for all non-deferred files.
5. Banner updates committed; PR cites `audits/evidence/mutation/banner.json`
   and per-crate JSON in the close ticket Acceptance.

The workflow that updates the banner is named in
`OWNERS.toml` `lanes.A.owner_globs`:
`.github/workflows/mutation-coverage.yml`. The full CI workflow
inventory is in `lane-a-floor/README.md` "CI workflow inventory"
subsection per W3 Lane A fix.

## Pointers

- Lane A README: `.planning/trajectory-5/lane-a-floor/README.md`
- Lane A PLAN: `.planning/trajectory-5/lane-a-floor/PLAN.md`
- Lane A tickets: `.planning/trajectory-5/lane-a-floor/planning docs`
- Mutation budget deep-dive: `.planning/trajectory-5/lane-a-floor/mutation-budget.md`
- Threat-evidence backfill deep-dive: `.planning/trajectory-5/lane-a-floor/threat-evidence-backfill.md`
- Risk Register R3 (deferred threat rows): `.planning/trajectory-5/architecture/RISK-REGISTER.md`
- Wave-2 sign-off: `.planning/trajectory-5/reviews/lane-a-wave2.md`
- Ship-bar tracker Bar 1 row: `.planning/trajectory-5/SHIP-BAR-TRACKER.md`

End of Bar 1 baseline.
