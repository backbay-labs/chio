# Wave 2B: threat model, five-mode ladder, TEE-compromise residual

Wave 1B (`research/wave1b-fresh-adversarial.md`) flagged three structural
gaps in a paper that the prior swarm had marked READY: a fuzzy threat
model (finding #2), a five-mode ladder defined only in a single §2
parenthetical (finding #5), and a §9 single-key-collapse row that
gestured at TEE closures without engaging the TEE-compromise literature
(finding #3). Wave 2B closes all three within scope. Builds are clean on
both `paper.tex` and `paper-usenix.tex`.

## Fix 1: §1 threat-model paragraph

`sections/01-introduction.tex` now carries a `\paragraph{Threat model.}`
block placed between the substrate-honest-by-assumption paragraph and
the contribution list. It states the adversary's in-scope capabilities
(controls the agent process, observes the attestation key, replays
signed receipts and attestations, attempts to forge attestation contents
that pass the constitution's sensor-set check), the out-of-scope
capabilities (cannot extract the TEE-rooted attestation key, cannot
suppress sensor-level reporting from a healthy sensor, cannot alter a
signed attestation after signing), and the protection target (the
verifier of a receipt rather than the operator of the signing kernel).

The paragraph cites `chioProgrammableSovereignty2027` for inherited
trust-store assumptions and forward-cites `sec:limits` for the
single-key-collapse residual. It reconciles the prior §1:6 statement
("the threat model controls the agent ... not the kernel's sensors")
with the §7:17 statement ("a kernel whose attestation lane is
compromised") by partitioning the cases: control of the agent (in
scope), compromise of the attestation key (out of scope, with the
residual named in §9). The block is roughly 200 words and resolves
Wave 1B finding #2.

## Fix 2: §2 five-mode ladder definitions

`sections/02-background.tex` previously named the five modes only in a
parenthetical (§2:9). That parenthetical is now retired in favor of a
`\paragraph{The five-mode trust ladder.}` block introducing the ladder
as a finite-tag construct with monotone admission stability, followed by
a bulleted list of one definition per mode (Observation, Receipt-backed,
Partition-contingency, Guarded, Quorum-required). Each definition gives
the admission floor in one line and notes the operational use case. The
block closes by naming "refuse" as the empty admission relation rather
than a ladder mode, and connects partition-contingency and
receipt-backed to the construction's structural decidability claim.

The list preserves the ordering already used elsewhere in the
prose (the existing references at §3:27, §5:13, §7:8 still resolve
without rewording). The bullet count is five with a sixth refuse case
named as a relation rather than a mode. The block adds roughly 280
words; the parenthetical it replaces was 12 words. The five-mode names
in the rendered PDF match the prose hits flagged in finding #5.

## Fix 3: §9 single-key-collapse engages TEE-compromise literature

`sections/09-limitations.tex` retains the attestation-key-isolation row
unchanged in claim but adds a new
`\paragraph{TEE compromise reduces the construction to single-key signing.}`
immediately after it. The paragraph concedes explicitly that a
hardware-root-of-trust closure for the prior row pushes the residual one
layer down rather than to zero, names the attack families that have
extracted enclave secrets in published work, and states that the
construction does not defeat these attacks and inherits the TEE root-of-
trust assumption.

The cited primary sources are: Plundervolt (`murdockPlundervolt2020`,
voltage-glitching against SGX, IEEE S&P 2020), Foreshadow
(`vanbulckForeshadow2018`, transient-execution key extraction from SGX,
USENIX Security 2018), Downfall (`moghimiDownfall2024`,
gather-data-sampling on recent Intel parts, USENIX Security 2024), and
Half-Double (`koglerHalfDouble2022`, Rowhammer-class fault injection on
commodity DRAM, USENIX Security 2022). The task brief suggested
TDX-Down; I substituted Foreshadow because the SGX/TDX downgrade
attacks share an attack family with Foreshadow's transient-execution
template and Foreshadow is the more canonical primary source a USENIX
reviewer recognizes. Wave 2A independently cites TDX-Down, Downfall,
and Plundervolt in another section under its own keys without
collision.

The paragraph closes by naming three candidate mitigations as future
work: hardware-enforced multi-key signing (sensing-side key distinct
from body-signing key, held in a separate cryptoprocessor), per-receipt
attestation-key rotation, and escrow-backed recovery from a compromise
window. The paragraph is roughly 145 words and resolves Wave 1B
finding #3.

## Fix 4: bib.bib TEE-compromise entries

Four new entries appended under a new section header (Section 15. TEE-
compromise primary sources): `murdockPlundervolt2020`,
`vanbulckForeshadow2018`, `moghimiDownfall2024`, and
`koglerHalfDouble2022`. All four resolve under bibtex with zero misses
on both `paper.tex` and `paper-usenix.tex`. Wave 2C subsequently
appended further entries; my entries remain at lines 410-450 of the
final bib.bib.

## Build verification

Final state:

- `paper.tex`: 0 errors, 0 undefined citations, 21 pages, 0 bib misses
- `paper-usenix.tex`: 0 errors, 0 undefined citations, 15 pages, 0 bib misses

USENIX gained 1 page (was 14) which matches the expected +1 from the
three structural additions. The 21-page article-class build held steady
because the additions absorbed into existing whitespace. No em-dashes
introduced. No new "this paper" voice violations introduced; the §9
edit removed one ("The strengthening of this paper") by rewriting it
to "The strengthening of the construction." The two remaining "this
paper" hits at §2:29 and §9:31 are pre-existing, out of scope, and
flagged in Wave 1B finding #8 for a separate polish pass.

## Files modified

- `sections/01-introduction.tex` (+15 lines, threat-model paragraph)
- `sections/02-background.tex` (+15 lines / -1 line net, five-mode list)
- `sections/09-limitations.tex` (+3 lines, TEE-compromise paragraph)
- `bib.bib` (+47 lines, four TEE-compromise entries with section header)
