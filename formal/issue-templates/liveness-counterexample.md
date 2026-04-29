---
name: TLA+ liveness counterexample (RevocationPropagation)
about: File a violation found by the nightly formal-tla-liveness lane against RevocationEventuallySeen.
title: "[liveness] RevocationEventuallySeen violated at <length=N> (<config>)"
labels:
  - formal
  - liveness
  - apalache
  - severity-needs-triage
assignees: []
---

<!--
This template is for liveness counterexamples produced by the nightly
`formal-tla-liveness` job (see `.github/workflows/nightly.yml`, wired in
M03.P3.T4) checking `formal/tla/RevocationPropagation.tla`. It is NOT for
safety violations of `NoAllowAfterRevoke`, `MonotoneLog`, or
`AttenuationPreserving` -- those are separate; file those against the
property-counterexample template (M03.P3.T5).

Drop the raw counterexample trace into `formal/tla/counterexamples/`
(the directory is preserved by `.gitkeep`) and link it from this issue.
The naming convention is:

  formal/tla/counterexamples/RevocationEventuallySeen-<UTC-date>-<short-sha>.txt

Apalache emits the trace in its own format; do NOT translate it. Reviewers
need the raw output to reproduce.
-->

## Property violated

`RevocationEventuallySeen` -- defined in
`formal/tla/RevocationPropagation.tla`. The property states:

> For every pair of authorities (a, b) and every capability c, if `a`'s
> local revocation epoch for c is non-zero, then `b`'s local revocation
> epoch for c eventually catches up to at least `a`'s value, under
> `WF_vars(PropagateAny)` (the top-level named-action form of weak
> fairness on Propagate; see comments in `RevocationPropagation.tla`).

If your counterexample is in fact a safety violation (one of
`NoAllowAfterRevoke`, `MonotoneLog`, `AttenuationPreserving`), close
this issue and refile against the safety counterexample template.

## Reproduction

Apalache version (capture from `apalache-mc version`):

```text
<paste here>
```

Exact command (paste from the failed CI step or local run; do not
reformat). Note: `RevocationEventuallySeen` is a temporal property
(uses the leads-to operator `~>`), so it is supplied to Apalache via
`--temporal=` and not `--inv=` (`--inv=` is reserved for state
invariants):

```bash
apalache-mc check \
    --temporal=RevocationEventuallySeen \
    --length=<N> \
    --config=formal/tla/MCRevocationPropagation.cfg \
    formal/tla/RevocationPropagation.tla
```

Config used (PR job is `PROCS=4, CAPS=8`; nightly liveness lane is
`PROCS=6, CAPS=16` per the phase doc):

- `PROCS = <int>`
- `CAPS  = <int>`
- `--length = <int>`
- Other flags: `<paste>`

CI run link (if applicable): `<URL to the GitHub Actions run>`

## Counterexample-trace excerpt

Paste the action-by-action prefix Apalache emitted, up to the lasso loop
or the unfair-action choice that fails the leads-to. Keep the original
formatting; line numbers in Apalache traces matter.

```text
<paste excerpt here; full trace lives in formal/tla/counterexamples/>
```

Full trace file (committed alongside this issue):

```text
formal/tla/counterexamples/RevocationEventuallySeen-<UTC-date>-<short-sha>.txt
```

## What the trace shows

1. Initial state summary (which `(a, c)` pair revoked first, what
   `rev_epoch[a][c]` becomes):
   - `<fill in>`
2. Which authority `b` fails to catch up, and why the relevant
   `Propagate(m)` is starved (or never enabled):
   - `<fill in>`
3. Whether the lasso loop violates weak fairness on `PropagateAny`
   (i.e. `pending` is non-empty in every state of the cycle but no
   `Propagate(m)` is taken). If it does, the model is unsound; if it
   does not, the property is genuinely violated and needs spec or
   implementation work.
   - `<fill in>`

## Severity-tier guidance

Pick exactly one and replace the `severity-needs-triage` label with the
matching label from the list. Severity drives release-gate posture in
`platform/release-gates/RELEASE_AUDIT.md`.

- `severity-blocker` -- the trace exhibits a behavior that the kernel
  can produce in production (no out-of-model assumption is required to
  realize it). Blocks the next platform release. Open a fix ticket
  immediately and link it from this issue.

- `severity-major` -- the trace is realizable only under a degraded
  fairness assumption (e.g. an authority that never processes its
  inbox), but the assumption is plausible (operator error, partial
  outage). Must be fixed before promoting the property to a
  release-gate invariant; does not block point releases that already
  pre-date the property.

- `severity-minor` -- the trace requires an unrealistic adversary
  (Byzantine scheduler, infinite suppression of a single authority) and
  is mitigated by an existing operational control. File a follow-up
  ticket to either tighten the model or document the assumption in
  `formal/assumptions.toml`. Does not block any release.

- `severity-spec-bug` -- the trace exposes a defect in the TLA+ module
  itself (over-specification, missing UNCHANGED, wrong type). Fix the
  spec, regenerate the nightly run, and close this issue with a link to
  the fixing PR. Does not block any release.

## Triage checklist

- [ ] Apalache version recorded above.
- [ ] Full counterexample trace committed under
      `formal/tla/counterexamples/` and linked from this issue.
- [ ] Severity label applied (one of the four above).
- [ ] If `severity-blocker` or `severity-major`: fix ticket opened and
      linked.
- [ ] If `severity-spec-bug`: PR opened against
      `formal/tla/RevocationPropagation.tla`.
- [ ] `formal/MAPPING.md` updated if the counterexample changes the
      Lean/Rust cross-reference for `RevocationEventuallySeen`
      (M03.P3.T5 introduces `MAPPING.md`).
