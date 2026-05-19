# Wave 3B: Ethics Considerations Appendix

## Scope

Drafted the mandatory USENIX Security Ethics Considerations appendix
(`sections/12-appendix-ethics.tex`) and wired it into both `paper.tex`
and `paper-usenix.tex` after the Open Science input added by Wave 3A.

## Structure

The appendix occupies the four USENIX-named categories:

- **Human and animal subjects.** States plainly that no human-subjects
  or animal-subjects research was conducted. The evaluation in
  Section~\ref{sec:evaluation} is over signed canonical-JSON records
  and verifier-side mutation outcomes; no PII was collected, analyzed,
  or stored. No IRB or animal-care protocol applies.

- **Responsible disclosure.** Declares that the construction
  introduces no new vulnerabilities; it is a verifier-side admission
  discipline consuming existing TEE attestation primitives. The
  TEE-compromise literature cited in Section~\ref{sec:limits}
  (Plundervolt, Foreshadow, Downfall, Half-Double) is identified as
  previously disclosed, CVE-published, and vendor-mitigated. The paper
  proposes no new attacks. No disclosure timeline was triggered, and
  no embargo applies.

- **Dual-use considerations.** Argues that the construction's primary
  beneficiary is the verifier; an attacker controlling the receipt
  body gains nothing from the substrate attesting its own posture.
  The marginal dual-use concern is verifier-role observability, which
  is intrinsic to any attested-system design and not unique to the
  sensor-grounded construction. No novel attack surface or
  side-channel is introduced.

- **Conflicts of interest.** Defers COI declarations to the
  camera-ready, in accordance with USENIX double-blind policy. States
  that no commercial relationship is foreclosed by the
  anonymous-review posture.

## Wiring

Both `paper.tex` (line 46) and `paper-usenix.tex` (line 69) now load
`sections/12-appendix-ethics.tex` immediately after the Open Science
appendix Wave 3A landed.

## Verification

`pdflatex` plus `bibtex` four-pass build is clean for both files:

```
article: errors 0 | pages 24
usenix:  errors 0 | pages 16
```

The `paper-usenix.tex` page count moved from 12 (per
SUBMISSION-CHECKLIST.md baseline) to 16; +1 page for Open Science
(Wave 3A) and +1 page for Ethics is plausible, with remaining growth
attributable to bibliography reflow on the new appendix labels. The
body remains 10 pages; references and appendices are excluded from
the USENIX 13-page body limit. Only pre-existing template font and
breakurl warnings appear in the logs; no warnings from the new
content.

## Voice and policy compliance

No em dashes (verified). No engineering-meta voice. No author
identifiers. The appendix describes what the construction does and
does not do, not project history.
