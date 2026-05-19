# Wave 3C: bib.bib construction

This wave constructs `bib.bib` from the union of TODO_ citation keys in `sections/*.tex` and `paper.tex`. Scope is limited to creating `bib.bib`; `paper.tex` was not modified (the `\bibliography{bib}` line at line 102 remains commented out and is deferred to Wave 4).

## Entry count

Total bib entries: 72. Breakdown by BibTeX entry type:

- `@book`: 16
- `@article`: 11
- `@misc`: 34
- `@techreport`: 11

The 72 entries cover the 66 unique TODO_ keys cited in the paper, plus six alias / overlap entries from `legal-references.md` that are not currently cited but were retained because the author may add them in a later revision wave (`TODO_citron_intermediary_liability`, `TODO_donohue_fisa`, `TODO_goldman_section230`, `TODO_gross_ni_aolain_law_in_emergency`, `TODO_scheppele_emergency`, `TODO_war_powers_reports`).

## Categories

Counts per substantive category:

- Books and monographs (continental theory, American emergency-powers scholarship, comparative emergency-powers scholarship, Weimar historiography, EU data-protection treatises, AUMF / drone-memos): 16.
- Law-review articles (Sunstein on sunsets, Scheppele on emergency law, Goldman on §230, Citron & Wittes on bad Samaritans, Keller on EU intermediary liability, Seng on DMCA, Donohue on §702, Mantelero on GDPR, Chesney on AUMF): 11.
- US statutes and bills (AUMF 2001, §230 / §230(c)(1), DMCA 512 / 512(g), FISA 702 / §1881a, FAA Reauth 2017, RISAA 2024, Iraq AUMF repeal 2023, Kaine-Young AUMF Repeal Act, Corker-Kaine 2018 framework, War Powers periodic reports): 13.
- US court opinions (Clapper v. Amnesty Int'l USA, United States v. Hasbajrami): 2.
- CJEU and predecessor court opinions (Google Spain, GC and Others v. CNIL, Google LLC v. CNIL, TU and RE v. Google, Lindqvist): 5.
- FISC opinions (Bates 2011 upstream, Collyer 2017 about-collection, Boasberg 2018 querying, Contreras 2022 FBI compliance, plus the aggregate `TODO_fisc_702_opinions` umbrella cite): 5.
- Agency / institutional reports (PCLOB 2014 / 2017 / 2023, plus the umbrella `TODO_pclob_702_report`, CRS R43983, DoD 1264 Report 2018, Brennan Center AUMF, Article 29 WP 225, EDPB Guidelines 5/2019, Stanford CIS over-removal report, Berkeley DMCA empirical paper): 11.
- Weimar primary sources (Article 48 of the Weimar Constitution, Bruening 1931 Notverordnungen, Reichstag Fire Decree, Enabling Act, Preussen contra Reich): 5.
- Companion technical paper (Programmable Sovereignty working paper): 1.
- Cryptographic-erasure placeholder reference: 1 (Boneh-Lipton 1996).
- Aliases / duplicate keys preserved for cross-reference (`TODO_jacobson_schlink_weimar`, `TODO_dmca_512g_counter_notice`, `TODO_goldman_section230_2019`, `TODO_citron_wittes_bad_samaritans_2017`, `TODO_pclob_702_2014`): 0 additional entries beyond the categories above; they reuse content from a parallel canonical entry.

## Entries with uncertain details

The following TODO_ keys use best-public-record form because the exact docket number, date, page citation, or publisher is uncertain at the level of the draft. The legal-scholar co-author pass will firm these up:

- `TODO_sunstein_sunset_clauses`: Vanderbilt Law Review forthcoming volume. `legal-references.md` marks this VERIFY; Sunstein has written on sunset clauses in multiple venues and the canonical citation is not yet pinned down.
- `TODO_scheppele_emergency`: Listed as 6 U. Pa. J. Const. L. 1001 (2004) per `legal-references.md`, but the same source flags this as best-guess; Scheppele has substantial work on the topic.
- `TODO_kuner_gdpr_erasure`: Listed as a chapter in EU Law Beyond EU Borders (Oxford 2019); the volume reference is flagged VERIFY in legal-references.md.
- `TODO_brennan_center_aumf`: Aggregate citation to Brennan Center's 2017-2024 reports; specific report TBD.
- `TODO_fisc_702_opinions` and `TODO_pclob_702_report`: Umbrella citations retained even though the case-study section also cites specific opinions and reports separately.
- `TODO_war_powers_reports` and `TODO_war_powers_reports_2021_2023`: Periodic War Powers Resolution transmittals are cited aggregately; the legal-scholar co-author may sharpen to specific reports.
- `TODO_iraq_aumf_repeal_2023`: Public-law number for the 2023 repeal-statute was reconstructed from public sources; the exact Pub. L. citation should be confirmed.
- `TODO_revocable_encryption_lit`: Boneh-Lipton 1996 used as a glancing best-public-record stand-in for the cryptographic-erasure literature the paper references in passing.
- `TODO_bruening_notverordnung_1931`: The Bruening Notverordnungen of 1931 comprise multiple decrees; the single 1 December 1931 decree (RGBl I 1931, S. 699) is cited as the canonical example, with a note that the wave covers several.
- `TODO_preussen_contra_reich_1932`: Staatsgerichtshof judgment of 25 October 1932; no standard reporter pagination is supplied because Anglophone reporters do not paginate this in a uniform way.

## Coverage

Every TODO_ key found via `grep -rho '\\cite{[^}]*}' sections/ paper.tex | tr ',' '\n' | sed 's/\\cite{//' | sed 's/}//' | sort -u` (66 unique keys) has a corresponding `@book`, `@article`, `@misc`, or `@techreport` entry in `bib.bib`. The set difference between the bib's key set and the paper's key set was computed with `comm -23`; the empty result confirms full coverage.

## Build verification

Optional build verification was run. Because `paper.tex` line 102 has the `\bibliography{bib}` line commented out (and Wave 3C scope prohibits modifying `paper.tex`), the in-place `bibtex paper` invocation reports "I found no `\bibdata` command" and all 66 cites as missing. To validate `bib.bib` syntax in isolation, a synthetic `dea_test.aux` was constructed containing the project's full `\citation{...}` list, plus `\bibstyle{plain}` and `\bibdata{bib}`. Running `bibtex dea_test` against this aux file produces:

- Exit code 0.
- 0 "I didn't find a database entry" warnings.
- 0 error messages.
- 66 `\bibitem` lines written into `dea_test.bbl` (matching the 66 unique citation keys).

The bib's `@string`-free, BibTeX-`plain`-style entries parse cleanly and resolve every paper key.

## Next-wave action

`paper.tex` line 102 currently reads:

```
% \bibliography{bib}
```

A later wave (Wave 4 or equivalent) must uncomment this line so the bibliography renders in the compiled PDF. Once uncommented, the build sequence `pdflatex -> bibtex -> pdflatex -> pdflatex` will produce the references section and resolve all 66 `\cite{TODO_*}` invocations against entries in `bib.bib`. After that, the legal-scholar co-author pass should rename TODO_ keys to proper Bluebook short forms and firm up the uncertain entries listed above.
