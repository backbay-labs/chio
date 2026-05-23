# Wave 4A: §3 cases tightening

## 1. §3.3 AUMF political-vs-structural triple-restatement

**Original (lines 403-421):** "The pattern admits both a political and a structural reading...The
structural reading this Article advances does not displace the political account; it identifies an
additional feature of the original grant that lowers the cost of continuation relative to
replacement at each successive period. The default at each successive period is continuation...that
structural asymmetry is the feature the typed-rollback grammar addresses, and it operates alongside,
not in displacement of, the political-equilibrium account."

**Change:** Replaced the two trailing restatements with a single combined sentence: "The structural
reading this Article advances operates alongside the political account rather than displacing it:
the original grant carries an additional feature that lowers the cost of continuation relative to
replacement at each successive period, and the typed-rollback grammar addresses that asymmetry."
Preserved Kaine-Young / Lee-Murphy / Corker-Kaine / 2023 Iraq AUMF repeal cites and the opening
"admits both a political and a structural reading."

**Delta:** -77 words.

## 2. §3.4 GDPR catalog paragraph → footnote

**Original (lines 261-269):** Body paragraph naming Lynskey, Bygrave, Mantelero, Kuner with full
publication metadata.

**Change:** Body retains one sentence: "The data-protection academic literature has framed the
right structurally rather than transactionally, but none of the leading treatments proposes a
typed-rollback discipline as the corrective." All named-scholar prose moved into a single
`\footnote{...}`. All four cites preserved inside the footnote.

**Delta:** -85 body words; the footnote carries the prose.

## 3. §3.1 Preußen contra Reich closing run-on

**Original (lines 99-105, 58 words):** "The structural reading this Article advances must
accommodate that ruling. The accommodation is that the structural absence of a typed rollback
witness made the ratchet structurally available, in the sense that nothing in the text or
surrounding architecture made the ratchet unconstructible; \emph{Preußen contra Reich} demonstrates
that the constitutional order's resistance to the ratchet was politically contested and partially
successful, which is consistent with the weaker structural reading but inconsistent with a strong
claim that the ratchet was textually entailed."

**Change:** Compressed to: "The structural reading this Article advances accommodates that ruling:
the absence of a typed rollback witness made the ratchet structurally available without making it
textually entailed, a narrower claim than \emph{Preußen contra Reich} disturbs." Preussen cite
remains at line 80 above.

**Delta:** -50 words.

## 4. §3.1 Kershaw/Mommsen/Caldwell named-scholar list → parenthetical cross-reference

**Original (lines 65-75):** Five-sentence enumeration naming Kershaw, Mommsen, Caldwell, Jacobson,
Schlink, Dyzenhaus with positional summaries of each.

**Change:** Compressed to: "The historiography on whether the Article~48 ratchet was structural or
political is contested (the Kershaw/Mommsen/Caldwell historiographical contestation discussed in
Part~\ref{sec:pattern}), and the primary-source record is collected in Jacobson and Schlink's
anthology \cite{TODO_jacobson_schlink_weimar} alongside Dyzenhaus's reconstruction of the
Kelsen-Schmitt-Heller debate \cite{TODO_dyzenhaus_legality_legitimacy}." `TODO_kershaw_hitler`,
`TODO_mommsen_weimar`, `TODO_caldwell_popular_sovereignty` cite keys remain present elsewhere in
§3.1 (lines 29, 37, 54).

**Delta:** -85 words.

## 5. §3.5 FISA 702 hedge-without-content fix

**Original (lines 367-371):** "The cryptographic literature on revocable encryption suggests that
some forms of collection can be made constructively reversible. Whether the construction is
operationally feasible in the surveillance context is an empirical question on which the Article
does not take a position."

**Change:** Merged the two adjacent sentences so the cryptography reference no longer asserts what
the disclaimer denies: "Whether such a construction is operationally feasible in the surveillance
context, including in light of the cryptographic literature on revocable encryption
\cite{TODO_revocable_encryption_lit}, is an empirical question on which the Article does not take a
position." Cite preserved.

**Delta:** -22 words.

## 6. §3.3 AUMF "clear instance" undercut

**Original (lines 437-438):** "the original AUMF's grant of unbounded authority is a clear instance
of the ratcheting pattern."

**Change:** Replaced "is a clear instance of" with "is the instance in which the structural absence
is most visible," removing the substantive judgment the surrounding disclaimer denies.

**Delta:** +5 words (longer phrasing).

## 7. Lowercase "the article" → "Article 48"

Six instances in §3.1 (lines 26, 31, 52, 69, 107, 112) all referred to Weimar Article 48 and were
replaced with "Article~48" (or "Article~48's" in possessive form). No GDPR Article 17 lowercase
"the article" instances were found in §3.4. No "this Article" instances needed capitalization.

**Delta:** ~0 words (token substitution).

## Totals

- File word count: 4,600 → 4,435 (delta **-165 words**).
- `\cite{TODO_*}` occurrences: 57 → 54 (3 redundant cite-calls dropped by Fix 4). **Unique cite
  keys: unchanged** at 53; all keys that were referenced before remain referenced.
- Em-dashes (U+2014): 0 (unchanged).
- Build verification: `exit:0`, 0 errors in log, PDF builds at 23 pages (unchanged from pre-fix
  count; the net body cuts moved into the §3.4 footnote rather than off the page).
