# Wave 1 Anonymization Audit -- Findings

Date: 2026-05-18
Scope: papers/programmable-sovereignty/paper.tex + papers/programmable-sovereignty/sections/*.tex
Target: double-blind submission (venue selected in W1.c; candidates NDSS 2027 Summer / USENIX Security 2027 Cycle 1)

## Summary

- Total findings: 2 (1 major, 1 minor)
- By severity: critical 0, major 1, minor 1
- Files swept: paper.tex, sections/01-introduction.tex through sections/10-conclusion.tex (10 section files), plus an auxiliary scan covering the bib citation labels referenced from prose
- Verdict: fixes queued (no blocking de-anonymization; one author-metadata edit and one optional softening recommended before submission)

The paper preamble uses `\documentclass[sigconf,anonymous,review,nonacm]{acmart}`, sets author to "Anonymous for external review", and routes email to `anonymous@example.org`. The body prose is clean of institution names, advisor names, repository URLs, filesystem paths, acknowledgments, funder names, grant numbers, IRB statements, branch identifiers, commit hashes, and personal-website / GitHub-handle signals. The two findings below are bounded and fixable with single-line edits.

## Signal-class enumeration

For audit completeness, every signal class from the task brief was checked across all in-scope files:

1. Institution / lab mentions tied to authorship: 1 finding (see Finding 1). External-org cites in body prose (Anthropic, OpenAI, DeepMind, METR, ARC Evals, AWS, Microsoft, NVIDIA, NIST, ETSI, EU) appear only as references to third-party frameworks or prior work, never as employer / affiliation, and are permitted under the task brief's signal-1 exception.
2. Self-referential cites that reveal authorship ("our prior work [X]", "extending our system Y"): Not present. The five contribution bullets in §1 use first-person plural in normal paper voice (`We give a substrate`, `We implement the construction`) without binding to a named prior artifact attributable to the authors.
3. Repository / branch / commit signals (GitHub usernames, branch names like `research/programmable-sovereignty-papers`, commit SHAs, PR numbers, internal `/Users/...` paths): Not present. The only `github` substring is the bib citation key `rekorGithub`, which is not rendered in the PDF body. No URL appears in body prose at all.
4. Acknowledgments paragraph: Not present. There is no `\section{Acknowledgments}`, no `\acks{}`, and no `\thanks{}` macro anywhere across paper.tex or the ten section files.
5. IRB / ethics-board mentions with institution names: Not present.
6. Funding sources with grant numbers or agency names tied to specific PIs: Not present.
7. System / project naming that uniquely identifies the author: 1 finding (see Finding 2). The legacy name "ARC" does appear once in body prose, but only as part of the external-org reference "ARC Evals" in §7 (the predecessor name of METR / Model Evaluation and Threat Research). It is not used in the project-name sense and METR is listed adjacent, which reads as a normal external-org reference. Flagged as minor for the requested human review.
8. URLs that resolve to author-identifying pages: Not present. No `https://` / `http://` strings in body prose.
9. First-person plural patterns implying a single identifiable group at scale ("we have been operating X for two years", "deployed at our customers"): Not present. First-person plural is confined to the conventional paper-voice idioms (`We close that gap`, `We give a substrate`, `We implement`) that are universal in double-blind submissions and not de-anonymizing.
10. Co-author leakage in absentia (acknowledgments naming Bowman / Perez / Walch / reviewers / private communications): Not present. No personal-communication credits exist anywhere in the manuscript, which is the correct state given the Walch embargo letter has not yet gone out.

## Findings

### Finding 1 -- Institution slot populated with project name
- File: papers/programmable-sovereignty/paper.tex:21
- Excerpt: `\affiliation{\institution{Chio Project}}`
- Signal: Under the ACM `anonymous` template the `\institution{}` field is conventionally redacted (left empty, or set to a placeholder such as "Anonymous Institution" or "Anonymous"). Filling it with "Chio Project" tells a reviewer that the artifact is maintained by an entity that self-identifies as a project rather than a university lab or industrial research group, which constrains the candidate-author space and reads as informal. It is not a direct de-anonymizer (no person, lab, or company is named), but the convention exists precisely so that reviewers see uniform anonymous metadata across submissions.
- Suggested fix: replace with `\affiliation{\institution{Anonymous Institution}}` (or omit the affiliation entry entirely, which `acmart`'s anonymous mode supports). Keep the project name "Chio" in the title, abstract, and body where it functions as the artifact name; the metadata slot is the only place this edit is needed.
- Severity: major

### Finding 2 -- "ARC Evals" external-org reference colocated with current project history
- File: papers/programmable-sovereignty/sections/07-discussion.tex:20
- Excerpt: `Capability evaluations (METR, UK AISI Inspect, ARC Evals) and frontier-safety frameworks (Anthropic RSP, OpenAI Preparedness, DeepMind Frontier Safety) bound what a model is likely to do`
- Signal: "ARC Evals" is the prior name of METR (Model Evaluation and Threat Research), which is in fact named immediately before it in the same parenthetical. As a citation to an external evaluation organization this is normal and not by itself de-anonymizing. The task brief flagged class #7 because the project has internally been renamed from "ARC" to "Chio" and asked whether the dual reference should be retained. A reviewer with knowledge of the rename could read this line as a coy nod to the internal name; a reviewer without that knowledge reads it as a routine list of capability-evaluation orgs. The risk is small but nonzero.
- Suggested fix: either drop "ARC Evals" and keep "METR" alone (since METR is the current name and one entry per org is cleaner), or keep both with a clarifying parenthetical such as "METR (formerly ARC Evals)" so the dual reference is explicit and unambiguous. Either edit removes the residual ambiguity.
- Severity: minor

## Notes for Wave 2

- Both findings are single-line edits localized to one file each.
- No body section requires structural rewriting.
- The author / email lines at paper.tex:20 and paper.tex:22 are already correctly redacted and need no change.
- The bib file (bib.bib) was not in scope for this audit; it should be verified separately if any cite contains a self-published preprint URL pointing at an author-identifying page. No such cite is referenced from body prose, so the risk is bounded to bib entries that the reviewer would only see if they consulted the bibliography directly.

## Verification

The findings file itself was grep-checked for U+2014 em dashes and contains none.
