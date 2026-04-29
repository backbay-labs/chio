# Reconcile-needed items for human review

**STATUS: RESOLVED 2026-04-29 via Option A.**

The single open item below was closed by adding M07.P6 (six tickets,
8 effort-days) which lands JVM / dotnet / Lambda / k8s verdict-matrix
drivers, registers them into the M02 P5.T6 hash-pinned manifest, and
flips the extended verdict-matrix workflow to required-CI. D07's
consequences in `decisions.yml` were rewritten to point at M07.P6
explicitly. The M07 narrative
(`07-adoption-beachhead-pack.md`) now enumerates P6 tickets in the
"Phases" section and lists deployment-shape SDK drivers in the "In"
scope. M07 totals: 40 tickets, 57.00 effort_days (was 34 / 49.00).

This file collected cross-trajectory ownership gaps surfaced by the
F-agent triage pass. It is retained as the audit trail.

## Items

### D07 defers JVM / dotnet / lambda / k8s SDK matrix to M07; M07 does not enumerate per-SDK tickets

**RESOLVED via Option A.** See `tickets/M07/P6.yml`,
`07-adoption-beachhead-pack.md` Phases P6 subsection, and D07
consequences in `decisions.yml`.

- **Source decision:** D07 (M02 cross-SDK matrix covers five primary
  kernels; JVM, dotnet, lambda, k8s deferred to M07).
- **M02 narrative wording:** "JVM, dotnet, lambda, k8s SDK drivers.
  Out-of-scope here; revisited in M07 (adoption beachhead) where each
  gets a per-SDK story."
- **M07 narrative state (pre-resolution):** did not name JVM, dotnet,
  lambda, or k8s in any phase, ticket, or out-of-scope clause. M07 P3
  + P4 deliver five new provider adapters (Gemini / Mistral / Groq /
  Ollama / Cohere) and two TS framework packages
  (`@chio/ai-sdk-middleware`, `@chio/next`); none of those are JVM /
  dotnet / lambda / k8s drivers.
- **Why deferred (not silently absorbed) at synthesis time:**
  absorbing four new SDK drivers into M07 would require an additional
  phase (P6) with at least 4-6 tickets and an additional 6-10
  effort_days. Adding that to M07 silently widens its scope past the
  synthesis brief and the agreed wave-3 ticket budget.
- **Resolution applied (Option A):** added `tickets/M07/P6.yml` with
  six tickets (T1-T6) covering one driver per deployment shape (JVM,
  dotnet, Lambda, k8s), the manifest registration + required-CI flip,
  and an integration smoke gate. M07 grows from 34 to 40 tickets and
  from 49.00 to 57.00 effort-days, a ~16% milestone-size increase
  inside the wave-3 capacity envelope. P6 work is non-trust-boundary;
  no freeze entry needed.

This item was the only currently-known gap in the decision register.
