# Chiodos 7.2 Tickets

- **C7.2-001, Integrator:** Create active planning docs, exact stacked
  baseline SHA, ticket map, final gates, no-planning-metadata rule, and 7.3
  shadow note.
- **C7.2-002, Runtime Evidence Contract:** Add runtime scenario, step evidence,
  proof source record, proof regeneration report schemas, fixtures, stable
  codes, and parser validation.
- **C7.2-003, Kernel Loopback Execution:** Rework runtime loopback so success
  evidence is structured and placeholder aggregate proof-parity artifacts cannot
  satisfy the success path.
- **C7.2-004, Local Provider Wiring:** Add static provider bindings for trust
  input, runtime policy, peer weights, admission bundles, authority artifacts,
  revocation material, and local evidence sinks.
- **C7.2-005, Runtime Trust Hardening:** Persist valid trust floors before later
  policy denial, bind verifier ids, harden peer weights, and add revocation
  freshness floors.
- **C7.2-006, Receipt Capture:** Capture signed kernel receipt ids and hashes,
  output hashes, request bindings, admission report hashes, lease ids,
  governance ids, and terminal step state.
- **C7.2-007, DSSE And Workflow Regeneration:** Generate strict bilateral DSSE
  and workflow receipt evidence from captured runtime records.
- **C7.2-008, Proof Package Regeneration:** Build a real
  `chio.chiodos.proof-package.v1` from runtime evidence and verify it with the
  existing verifier.
- **C7.2-009, Parity And Drift Guard:** Compare runtime-regenerated proof
  packages against the static three-vendor fixture on stable semantic fields.
- **C7.2-010, Negatives And Gates:** Add executable negatives, gate scripts, CI
  path triggers, docs refresh, final verification, PR, review-thread cleanup,
  and post-merge gate rerun.
