# Current State Inventory (input for debate swarm)

As of 2026-05-18. Single source of truth the 4 debate agents share.

## Papers — done / ready to submit

**Parent paper: "Programmable Sovereignty: Lean-Attestable Constitutions Over Capability-Bounded Federated Receipts"**
- Location: `arc/papers/programmable-sovereignty/`
- Status: 13 pages acmart, 4-pass build clean, 0 errors / 0 undefined / 0 BibTeX warnings, paper.tex and v1.tex byte-identical
- Polish history: 5 polish passes + 8 swarm iterations + 4 post-execution reviews
- Lean substrate: 130 theorems in `formal/lean4/Chio/Chio/` including V1 PredicateLang, V3 lane-quorum, V4 meta-stability, V5 trajectory-invariant, BilateralAccept
- Companion paper-usenix.tex sibling build (16 pages article-class)
- Items pending: Walch pre-disclosure letter SEND (drafted), IC3/Paradigm/GovAI Pre-Slack (drafted), Anthropic co-author outreach (drafted, Bowman/Perez/Grosse/Kaplan), M2 title decision (deferred until Walch response)

**Sensor-Grounded Admission paper: "Sensor-Grounded Admission: Polity Receipts with Attested Substrate State"**
- Location: `arc/papers/sensor-grounded-admission/`
- Status: 18 pages article-class (~12-13 conference template), 0/0/0 build clean, 32-entry bib, mechanized Lean (4 theorems, no `sorry`, kernel axioms only)
- Closed in 14 fires across 3 cycles + closeout + final adversarial review (zero substantive findings)
- Recommended primary venue: USENIX Security 2027 Cycle 1 (deadline 2026-08-25)
- Items pending: conference template conversion, anonymization, optional Lean appendix

## Papers — v0 drafts (need substantial work)

**Reversible Action (Paper N1): "Programmable Sovereignty Over Reversible Action"**
- Location: `arc/papers/reversible-action/`
- v0 drafted in one fire; ~6500 words
- Critical gate: the rollback-amendment composition theorem may be `rfl`. Cycle would need to write the Lean statement first and verify non-`rfl` before committing.
- Status: draftable-with-work; 4-5 months to defensible USENIX Security submission if gate clears

**Delegated Emergency Authority: "Delegated Emergency Authority as Bounded Executive Action"**
- Location: `arc/papers/delegated-emergency-authority/`
- v0 drafted; ~10000 words; cross-disciplinary (law journal target)
- Five case studies: Weimar Article 48 (strongest), Section 230, GDPR Article 17, FISA 702, AUMF 2001
- Status: needs legal co-author (Walch primary, then Huq/Sunstein/Scheppele/Keller/Jaffer); 12-18 month timeline
- Cross-disciplinary risk: CS overclaim into law

**Agentic Tool Safety: "Tool Calls as Reversible-Action Admission"**
- Location: `arc/papers/agentic-tool-safety/`
- v0 drafted; ~5700 words; position paper using parent substrate
- Anthropic co-author hook (Perez primary recommendation)
- Status: 2-3 weeks to workshop-ready (NeurIPS Safe-AI workshop, ICML AI Safety); publishable at workshop tier without co-author, top conference needs one

## v2 substantive engineering (V-tier from parent paper action plan)

All have design memos in `arc/papers/programmable-sovereignty/swarm-notes/`:

- **V2**: Real two-kernel federation across real network boundary. 3-tier plan (Docker localhost / two-host LAN / cross-region WAN). gRPC over TLS via `tonic`. Tier-1 estimated 2-3 weeks.
- **V6**: 30+ Chiodos buyer-closure replay fixtures wired into tests/replay/. Design lists 8 new families. Manifest authoring + `--bless` golden generation deferred (policy-gated).
- **V7**: Threshold cosigning (FROST/ROAST) for two-key DSSE binding. ZF `frost-core` v2.x selected (RFC 9591). Library commitment + DKG ceremony + coordinator transport deferred.
- **V8**: Issuer-rotation epoch binding for BBS derivation. Schema-v2 wire bump + Merkle-rooted rotation log. Workspace-wide commitment + operator runbook deferred.

## Clawdstrike integration thread (separate but related)

`arc/.planning/clawdstrike-chio-brainstorm/` (10 files from prior brainstorm swarms):
- Peer handoff identified clawdstrike EDR as the OS-grounded sensor layer Chio formal model lacks
- The reversal: "what can Chio steal from clawdstrike" — converged on bounded executive action (TTL + rollback) as highest-leverage steal; led to drafting Paper N1 reversible-action
- The sensor-grounded admission paper just shipped is the FIRST chio-from-clawdstrike steal landed
- Open question: should Chio (formal model + Rust crates) integrate further with clawdstrike (real OS sensors + production EDR), or stay in formal-model lane?

## Other items

- **Walch pre-arXiv embargo letter** drafted at `papers/programmable-sovereignty/swarm-notes/walch-invitation-draft.md`; needs human signature
- **Anthropic co-author outreach memo** drafted; Perez recommended primary for sensor-grounded, Bowman for parent
- **NDSS 2026 / USENIX Security 2026 simultaneous-submission policy check** completed
- **Appendix C: Compound 289 worked retrospective** drafted at `papers/programmable-sovereignty/appendices/appendix-c-compound-289.tex`; ready to include in parent if page budget permits
- **Case-study pilot decision**: UK AISI / AI cross-lab red-team attestation picked
- **Next-paper-pipeline items** in parent paper's action-plan-progress.md:
  - Paper 3: Hart conditions (b)+(c) sociological study, Yale/Harvard JOLT Q1 2027
  - Paper 4: trajectory-invariant constitutions, POPL 2028 Jul 2027
  - Paper 5: adversarial-replay benchmark, USENIX Security 2027 full / NSDI 2027 (potentially subsumed by clawdstrike's replay engine if integration happens)

## Author constraints

- Solo author (presumably) with optional co-authors to recruit
- Has full control of arc/ and clawdstrike/ codebases
- Has not yet sent any external outreach (Walch, Anthropic, IC3)
- Has run autonomous research/writing cron loops successfully
- Has been protective of paper voice — engineering-meta narration is a recurring complaint
