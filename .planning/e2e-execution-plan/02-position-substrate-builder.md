# Substrate Builder Position

## Headline argument (one paragraph)

Papers are downstream artifacts. The substrate (Chio Rust crates + Lean formal model + the clawdstrike empirical chapter) is the asset that compounds. Every paper in the current pipeline (parent, sensor-grounded, reversible-action, delegated-emergency, agentic-tool-safety, the Hart sociological, the trajectory-invariant POPL, the replay-benchmark) inherits the same five limitations the parent paper inherits today: macOS ES sensor is stubbed, federation is in-process, party-independence rests on key separation rather than threshold cryptography, issuer-rotation is a TODO, and the replay corpus is 50 fixtures across a thin family count. Submit the parent paper now and every one of those eight papers ships with those same caveats baked in. Spend the next 12-14 weeks shipping V2 + V6 + V7 + V8 and then submit, and every subsequent paper rides on a substrate that has retired four of the five caveats. The marginal value of one early submission is small. The marginal value of a substrate that doesn't have to apologise for itself is huge.

## The 12-month substrate-first plan

Sequencing is chosen for paper-strengthening-per-engineering-week, not for technical elegance.

**Weeks 1-3: V2 tier-1 (Docker localhost two-kernel federation).** Highest paper-strengthening-per-week, by a wide margin. The single most damaging line in any honest reviewer report on the parent paper is "federation tests run in-process within a single Rust binary." V2 tier-1 retires that exact line at the cost of ~2-3 weeks of `tonic` + TLS + DSSE-over-the-wire plumbing. Every downstream paper that cites federation behaviour (parent, sensor-grounded, agentic-tool-safety) gets a stronger §6 from this single change. Defer tier-2 (two-host LAN) and tier-3 (cross-region WAN); tier-1 is enough to retire the in-process critique because the receipt machinery, the gRPC transport, and the DSSE binding are real even if both kernels happen to share a Docker network.

**Weeks 3-5: V6 (replay corpus to 80 fixtures across 18 families).** Cheap, high-leverage. The parent paper's §6 currently reports 50 fixtures; the design memo lists 8 new families ready to wire in. This is mostly authoring work plus a small `--bless` policy gate. The unlock is that the replay-benchmark paper (Paper 5 in the parent's pipeline) becomes a defensible USENIX Security submission rather than a "we have 50 fixtures, want more, please" position piece. V6 also lets the parent paper's adversarial-replay table grow from a stub to a substantive contribution.

**Weeks 5-11: V7 (FROST threshold cosigning).** This is the big cryptographic win. The current two-key DSSE binding rests on "we use two different keys held by different parties." A reviewer with crypto credentials reads that and writes "this is key separation, not threshold cryptography, and party-independence is a deployment assumption rather than a theorem." FROST + RFC 9591 + ZF `frost-core` v2.x makes party-independence a cryptographic property: no t-1 subset can forge a co-sig, full stop. This unlocks the strongest version of the parent paper's federation claim and is load-bearing for any future paper that makes claims about Byzantine-tolerant attestation.

**Weeks 9-14: V8 (BBS issuer-rotation epoch).** Runs partially in parallel with V7 because it touches a different subsystem (BBS derivation, schema-v2 wire bump, Merkle-rooted rotation log). The unlock is that the parent paper's "issuer-rotation is a TODO" footnote becomes a "issuer-rotation is mechanised under epoch t, key compromise at epoch t-1 cannot retroactively forge receipts." That is a clean theorem statement the Lean model can carry.

**Weeks 14-26: clawdstrike empirical-chapter integration.** Once V2-V8 land, the formal model and Rust crates have receipts to point at. The next twelve weeks are spent making the clawdstrike branch state usable as the empirical chapter for every paper going forward: the macOS ES sensor is no longer stubbed, the Network Extension produces real attested events, and the sensor-grounded admission paper graduates from "12-page article-class with stubbed sensor" to "USENIX Security submission with real attested macOS event stream."

**Weeks 26-52: harvest.** Submit parent paper to USENIX Security 2027 Cycle 2 or NDSS 2028 with V2-V8 retiring all four caveats. Submit sensor-grounded to USENIX Security 2027 Cycle 1 with real ES sensor. Submit replay-benchmark to NSDI 2027 with 80-fixture corpus. Submit agentic-tool-safety to NeurIPS Safe-AI workshop 2026. Three to four submissions in 2027 that ride on a substrate worth riding on.

**First V item to build: V2 tier-1.** Highest paper-strengthening-per-engineering-week and the most-cited critique it retires.

## The clawdstrike question

**Verdict: full integration, but framed correctly.**

The wrong framing is "merge Chio into clawdstrike" or "merge clawdstrike into Chio." Neither product wants the other's accidental complexity. The right framing is that clawdstrike is the empirical chapter for every Chio paper from now until the formal model has a second comparable empirical anchor (which it doesn't, and won't, for at least two years).

The sensor-grounded admission paper already validated this: a Chio formal-model paper became defensible the moment it could point to a real OS sensor producing attested events. That paper landed in 14 fires across 3 cycles. Without the clawdstrike sensor layer it would have been a position paper at best.

Specifics of full integration:

- The clawdstrike branch state (97 modified + 32 untracked, ~79K LOC uncommitted on `fix/macos-es-ne-hardening`) is treated as the canonical macOS empirical chapter for the next 24 months of Chio papers.
- Chio formal-model claims that reference OS-level enforcement (admission, sensor-grounded attestation, network-extension events) cite clawdstrike as the production-grade reference implementation, not the toy Rust kernel in `crates/chio-kernel`.
- The reverse direction (what Chio steals from clawdstrike) continues: bounded executive action was the highest-leverage steal, reversible action is the second, and the trajectory-invariant POPL paper will likely steal a third.
- Operationally: the `fix/macos-es-ne-hardening` branch is not landed as one commit. It is split into ~6-10 reviewable PRs over the V2-V8 window so that each Chio paper that cites clawdstrike points to a specific landed commit, not a branch that may rebase.

Light integration loses the empirical chapter. Skip integration and every future Chio paper inherits the parent paper's "the OS sensor is stubbed" critique forever.

## Papers as downstream artifacts

Mapping substrate work to paper unlocks:

- **V2 unlocks**: parent paper §6, sensor-grounded §3 (federation context), agentic-tool-safety §4 (tool-call attestation across kernels), reversible-action §5 (rollback federation).
- **V6 unlocks**: parent paper §6 (table grows from stub to substantive), replay-benchmark paper (the entire paper). Without V6 the replay-benchmark paper is not viable.
- **V7 unlocks**: parent paper §4 (party-independence becomes a theorem), reversible-action §6 (rollback authority cosigning), delegated-emergency §7 (Article 48 case study gets a cryptographic analogue).
- **V8 unlocks**: parent paper §5, sensor-grounded §5 (issuer rotation under attested OS state), Hart sociological paper (issuer rotation as legitimacy proxy).
- **Clawdstrike empirical chapter unlocks**: sensor-grounded final submission, agentic-tool-safety conference-tier (not workshop-tier), the trajectory-invariant POPL paper's empirical section, the replay-benchmark paper's "does this work on real OS sensor traces" section.

Papers that need V2-V8 + clawdstrike to be defensible at top venues: 7 of the 8 in the current pipeline. The only one that doesn't strictly need them is the delegated-emergency law-journal paper, which is cross-disciplinary and bottlenecked on Walch.

## Risk profile

**Over-investing in substrate.** The real risk is that V7 (threshold cosigning + DKG ceremony + coordinator transport) slips from 6 weeks to 12 weeks because crypto plumbing always slips. Mitigation: ship V2 + V6 first (5 weeks total, retires the two most-cited critiques), then commit to V7 + V8 with a hard 14-week cap. If V7 slips past 14 weeks, submit the parent paper with V2 + V6 + V8 and a "threshold cosigning is in-progress, party-independence currently rests on key separation" footnote, which is honest and survives review.

**Under-investing in substrate.** Submit the parent paper now to USENIX Security 2026 Cycle 2. It is 13 pages acmart, 4-pass build clean, 130 theorems mechanised. It will probably get into a top venue. But every paper that cites it for the next five years cites a paper with a stubbed sensor, in-process federation, key-separation rather than threshold-cosig, and a 50-fixture replay corpus. That is not a temporary embarrassment; it is the load-bearing critique against the entire Chio research programme until somebody re-does it. And the somebody who re-does it is you, with V2-V8, in 2027, at which point you have to write a follow-up paper that says "the substrate critiques in our 2026 paper have been retired" which is a much worse paper than the one you would have submitted in 2027 if you had just held the parent paper for V2 in the first place.

The asymmetry is severe. The downside of holding is a ~14-week submission delay. The downside of submitting now is a five-year tail of "the 2026 paper assumed an in-process federation; this matters because [the reviewer's actual paper]."

## Anticipated counter-arguments and rebuttals

**The pragmatist will say: "Ship the parent paper now. Walch letter is drafted. The submission deadline is real. The substrate work will happen anyway, and the next paper that rides on V2-V8 can simply cite the retired caveats. Holding is theatre."**

Rebuttal: the substrate work will *not* happen anyway. Substrate work happens when there is an unshipped paper that motivates it. Ship the parent paper and the motivation to ship V2 within 3 weeks evaporates, because the paper is in review and V2 doesn't help the in-review version. V7 + V8 slip indefinitely. This is observable: V6's design memo has been ready for months and the corpus is still at 50 fixtures. The forcing function for substrate work is an unshipped paper. Burn that and the substrate stagnates.

Furthermore: "the next paper can cite the retired caveats" assumes the next paper's reviewers will read the next paper, not the 2026 paper. Reviewers cite the most-cited prior work. The 2026 paper will be the most-cited Chio paper for at least 3 years, and its caveats will be the caveats every reviewer cites against every follow-up.

**The scholar will say: "The papers ARE the substrate from a research-programme perspective. The 2026 parent paper establishes the formal model and the conceptual frame. Engineering substrate matters for production deployment but the research contribution is the Lean model, which is mechanised, complete, and ready."**

Rebuttal: the Lean model has 130 theorems but the parent paper's empirical §6 is what reviewers will ask about, and what gets cited. The research contribution survives the engineering caveats only in the eyes of theory-only reviewers. Empirically-grounded reviewers (USENIX Security has many) will read §6 first and §4 second. The Lean model is the strongest part of the paper; the empirical chapter is the weakest. The substrate work strengthens the weakest chapter without touching the strongest. There is no theoretical loss from holding.

**Both will say: "The clawdstrike branch is uncommitted by accident, not by design. 79K LOC on `fix/macos-es-ne-hardening` is technical debt, not an empirical chapter."**

Rebuttal: it is both. The branch is uncommitted because nobody has had time to split it into reviewable PRs. The work is real; the macOS ES sensor hardening on that branch is the empirical foundation for sensor-grounded admission and will be the empirical foundation for every Chio paper that cites OS-level enforcement. The right move is not to abandon the branch as technical debt; the right move is to split it into 6-10 reviewable PRs over the V2-V8 window so each one lands cleanly and each Chio paper that cites it points to a landed commit.

---

**Bottom line.** First V item: V2 tier-1. Clawdstrike verdict: full integration as canonical empirical chapter. Parent paper submission: hold until V2 ships (~3 weeks), submit then.
