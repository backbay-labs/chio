# Ticket Map

- C7.3-001, Integrator: Create branch, planning docs, baseline SHA, ticket map,
  final gates, no-planning-metadata rule, and 7.4 shadow.
- C7.3-002, Runtime Evidence Manifest: Add schemas, types, validation, and
  canonical hash binding over workflow reports, step evidence, admission
  reports, receipts, DSSE, and source material.
- C7.3-003, Package-Valid Receipt Capture: Replace synthetic loopback receipt
  JSON with package-ready signed `ChioReceipt` artifacts.
- C7.3-004, Strict DSSE Emission: Emit strict Chiodos DSSE envelopes from
  runtime proof material.
- C7.3-005, Workflow Receipt Assembly: Emit signed `WorkflowReceipt v2` evidence
  with parent chain, output hashes, DSSE hashes, destructive flags, governance
  refs, and vendor signatures.
- C7.3-006, Runtime Proof Package Builder: Assemble
  `chio.chiodos.proof-package.v1` from runtime proof material and verifier-owned
  trust/context inputs.
- C7.3-007, Verifier Integration: Accept regeneration only when the existing
  Chiodos verifier accepts the regenerated package.
- C7.3-008, Proof Parity Report: Compare static and runtime-regenerated
  three-vendor packages on stable semantic fields.
- C7.3-009, Negatives And Gates: Add executable checks for pending-marker
  rejection, proof artifact hashes, verifier acceptance, and stable failure
  code handling.
- C7.3-010, Docs And Closeout: Refresh docs, update CI triggers, run gates,
  open PR, resolve review threads, merge, and rerun on `main`.
