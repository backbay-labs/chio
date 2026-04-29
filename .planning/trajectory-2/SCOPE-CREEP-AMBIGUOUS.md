# Scope-creep ambiguities for human review

This file is the audit output of the scope-creep + anti-pattern audit
pass over `.planning/trajectory-2/`. It records items the audit agent
flagged as potentially out-of-scope but did NOT remove because the
classification is ambiguous. Decisions here belong to a human reviewer.

## Resolution status

- M07.P5.T2 `fastapi-langchain` template: **RESOLVED**. D18 explicitly
  names FastAPI + LangChain as one of the three in-scope templates. The
  synthesis cut named the `chio-langchain` SDK SCAFFOLD-FILLIN package
  (a framework adapter), not the LangChain framework as a starter-
  template primitive. Both M07 narrative items (template name and
  description) are decision-backed and stay.
- M07 narrative LangChain mention: **RESOLVED** by the same reasoning.
- M06 Miri / Shuttle FFI lane silence: **OPEN** (not in M07/M08 lane;
  passed through to the M06 F-agent or human reviewer).

## Items flagged but not removed

### M07.P5.T2 - `fastapi-langchain` template uses LangChain itself (resolved; retained)

The cut list excludes "SDK M14 (LangGraph/CrewAI/AutoGen scaffold
fillin)". M07.P5.T2 ships a `fastapi-langchain/` template under
`sdks/typescript/templates/` that wraps a LangChain agent through the
trajectory-1 Python SDK. The template imports LangChain itself (not
LangGraph), and the `gate_check.cmd` only verifies the FastAPI app
imports cleanly. No LangGraph / CrewAI / AutoGen code is shipped.

Reasoning for retention: the cut named LangGraph specifically as a
framework adapter; LangChain is the underlying primitive used as a
usage example, and the template is one of three named in decision D18
(Next.js / FastAPI / Cloudflare Worker).

If the human reviewer reads "LangGraph" as a stand-in for "any agent-
framework integration in a starter template", this template should be
replaced with a minimally-scoped FastAPI + httpx example that does not
import an agent framework. The audit agent did not make that change
because the template choice is recorded in decisions.yml D18 and a
unilateral edit would contradict a locked decision.

### M07's narrative names "LangChain" once in P5.T2 description (resolved; retained)

The narrative for M07.P5.T2 reads "Python FastAPI app wrapping a
LangChain agent through the trajectory-1 Python SDK". This phrasing
is consistent with the template directory name above; same reasoning
applies. No edit was made because the wording is descriptive of an
existing, decision-backed deliverable.

### M06's silence on Miri / Shuttle FFI lane (resolved; M02 is canonical)

The cut list says "Quality M15 (Miri + Shuttle FFI lane) - Folded
into M06 perf hardening CI". M06 currently says nothing about a
Miri / Shuttle FFI lane in either its In or Out lists. The audit
agent did not add it as Out-and-why because:

1. The cut record claims it folds into M06 "as a future
   consideration", which is a vague directive.
2. M06's six phases are fully scoped without it.
3. Adding Miri / Shuttle work to M06 Out (instead of In) is the
   correct interpretation, but the language ("folded into") could
   be read as either "land in M06" or "owned-but-deferred-by M06".

If the reviewer reads "folded into M06" as "M06 must Out-list it",
M06's Out section should gain a one-line entry. The audit agent left
it untouched because M02's Out list already names it, which is
sufficient for scope discipline.

**Resolution (cross-cutting triage 2026-04-29):** M02 is the canonical
declining milestone. Per the spirit of D11 (Kani harness ceiling
discipline: shuttle/miri/mutants pay better at the margin than another
Kani harness), M02 owns the mutation/shuttle/miri scope contract, and
its Out list already names the Miri + Shuttle FFI lane explicitly. The
"folded into M06" phrasing in the cut record refers to long-tail
performance-side investigation that M06 may opportunistically pick up
under its existing perf-hardening lane; it is NOT a hand-off requiring
an M06 Out-list entry. M06's Out list remains unchanged. This
ambiguity is RESOLVED with no edit to M06; M02 stays canonical.
