# Programmable Sovereignty Reading Notes

This draft is grounded in the local Chio protocol, Chiodos doctrine, live treaty branch, formal proof manifest, and branch-specific audit notes.

- `docs/research/CHIODOS_CONCEPT.md` v1.1 retired the broad agent-nation-state frame because the live treaty, buyer closure, and proof substrate were not yet present.
- `spec/PROTOCOL.md` defines Chio as a capability-scoped mediation and evidence system, with canonical JSON for signed artifacts and explicit non-claims around global consensus and unbounded proof coverage.
- `spec/CHIODOS_LADDER.md` defines the five ordered ladder modes and the ladder-intersection reconciliation rules.
- `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` identifies the gap in existing in-toto predicates: joint intent by two named organizations after independent local policy evaluation.
- `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` keeps Ed25519 over canonical receipt bytes authoritative and treats BBS disclosure as an opt-in secondary commitment.
- The live worktree `/Users/connor/.codex/worktrees/985a/arc` contains the Chiodos runtime treaty and admission-hook implementation cited by this paper.
- The current checkout contains four new Lean theorems for bounded treaty intersection and amendment refinement in `formal/lean4/Chio/Chio/Treaty/Intersection.lean`.
