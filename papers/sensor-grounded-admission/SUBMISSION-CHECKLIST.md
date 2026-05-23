# Sensor-Grounded Admission -- Submission Checklist

Target: USENIX Security 2027 Cycle 1 (deadline 2026-08-25)
Generated: 2026-05-18 by W4.a verification pass

## Gates

### 1. Build gate (make submit-check)

- [x] `make submit-check` exit 0 -- VERIFIED 2026-05-18
- [x] 4-pass pdflatex clean (pass 1, 2 (bibtex), 3, 4 each exit=0) -- VERIFIED
- [x] `[check-log] OK` (no `!`, no undefined refs, no citation warnings) -- VERIFIED
- [x] `[check-bibtex] OK` (no `Warning--`, no error markers in .blg) -- VERIFIED
- [x] `[check-pages] paper-usenix.pdf: total=12, refs start page=11, body=10 (max=13)` -- VERIFIED
- [x] VERDICT: PASS (paper-usenix is submission-ready) -- VERIFIED

### 2. Body page count

- [x] Body = 10 pages, references begin page 11, total 12 -- VERIFIED via check-pages output
- [x] USENIX Security body limit 13, references and appendices excluded -- VERIFIED in Makefile (MAX=13)

### 3. Anonymization

- [x] Author block: `Anonymous Author(s) / Anonymous Institution` in both paper.tex and paper-usenix.tex -- VERIFIED
- [x] No personal-identifier institution names tied to authorship -- VERIFIED
- [x] No "we previously" / "we have previously" patterns -- VERIFIED (zero matches)
- [x] No internal paths (`/Users/...`, branch names, GitHub handles) in body, sections, bib -- VERIFIED (zero matches)
- [x] No acknowledgments paragraph, no IRB statement, no funding statement -- VERIFIED (zero matches)
- [ ] Substrate identifier "Chio" appears in body (Section 1, Section 8) and bib entry `chioProgrammableSovereignty2027` -- NOTED for human review. The cited parent paper is the natural author-identifying artifact under double-blind. USENIX double-blind policy generally permits citation of one's own prior work in third person; the bib uses `{Chio Project}` as author rather than a personal name. The human should confirm this matches their interpretation of the venue's double-blind guidance before submission, but it is not a clear violation.

### 4. Voice rule (em dashes, engineering-meta)

- [x] No U+2014 em dashes in paper.tex, paper-usenix.tex, sections/*.tex -- VERIFIED
- [x] No U+2014 em dashes in supplementary/* -- VERIFIED
- [x] No "the construction defended here", "the live implementation", "the codebase", "checked-in fixtures", "bless recipe", "release-engineering", "we extend", "we introduce" -- VERIFIED (zero matches)
- [x] No project-version refs ("v1/v2/v3" as changelog cadence); the only `v3` match is the USENIX template filename `usenix2019_v3.sty` -- VERIFIED
- [x] No internal artifact counts ("125 Rust crates", "113 Lean theorems") as headline content -- VERIFIED
- [x] No branch names, wave/swarm/orchestrator/PR terminology in body -- VERIFIED (the "branches" hit is a scientific-genealogy use in related-work, not a VCS branch)

### 5. Supplementary package

- [x] `supplementary/lean-source.tar.gz` exists, 40.2 KB (41194 bytes) -- VERIFIED
- [x] Tarball extracts cleanly to `chio-lean/` (lakefile.lean, lean-toolchain v4.28.0-rc1, Chio.lean root, Chio/ subtree) -- VERIFIED
- [x] `lake build` exits 0, 24/24 jobs, wallclock 11.48 s on warm cache -- VERIFIED
- [x] `Chio.Treaty.SensorGroundedAdmission` builds at job 10 of 24 (matches README) -- VERIFIED
- [x] `supplementary/proof-manifest.toml` parses as valid TOML (keys: manifest, theorems) -- VERIFIED
- [x] `supplementary/theorem-inventory.json` parses as valid JSON -- VERIFIED
- [x] Four sensor-grounded theorems present and consistent across both files -- VERIFIED
  - `admission_predicate_separates_healthy_and_degraded_witnesses`
  - `partition_contingency_mode_iff_degraded_subset`
  - `healthy_attestation_required_for_destructive_admission`
  - `degraded_sensor_admission_requires_re_admission_witness`
- [x] `#print axioms` reports only `propext`, `Classical.choice`, `Quot.sound` -- VERIFIED by `lake env lean PrintAxioms.lean`
- [x] No `sorry`, no project-local `axiom` declarations anywhere in the Chio/ tree -- VERIFIED (zero matches)
- [x] `supplementary/README.md` exists, 72 lines (well under one page) -- VERIFIED

### 6. Bibliography hygiene

- [x] No author-identifying personal GitHub URLs (all github.com URLs point to institutional repos: secure-systems-lab/dsse, linux-audit, apple/security-pcc, aws/aws-nitro-enclaves-nsm-api) -- VERIFIED
- [x] No "preprint at https://github.com/<username>/..." patterns -- VERIFIED (zero matches)
- [x] No grant numbers, NSF, DARPA, fellowship, funded mentions in note fields -- VERIFIED (zero matches)

### 7. USENIX-template-specific

- [x] Title identical (paper-usenix adds template formatting tags `\Large \bf`, acceptable per task spec) -- VERIFIED via diff
- [x] Abstract identical byte-for-byte between paper.tex and paper-usenix.tex -- VERIFIED via diff
- [x] `\bibliographystyle{plain}` in both papers (USENIX-compatible) -- VERIFIED
- [x] No stray `\thispagestyle{empty}` first-page suppression -- VERIFIED (zero matches)
- [x] `usenix2019_v3.sty` present in paper directory (build is self-contained) -- VERIFIED

### 8. Open Science statement preparedness

- [x] `supplementary/README.md` provides material adaptable for the Open Science appendix (Files list, build instructions, axiom verification, theorem inventory) -- VERIFIED
- [ ] Open Science appendix (~1 page) not yet written into paper sections -- NOT DONE, drafting work for the human

### 9. Ethics Considerations preparedness

- [ ] No `ETHICS.md`, `ethics-considerations.tex`, or equivalent draft in repo -- VERIFIED ABSENT
- [ ] No Ethics Considerations section in body -- VERIFIED ABSENT
- [ ] Ethics Considerations appendix (~1 page) must be drafted before submission. The paper is formal-substrate work without human subjects, but USENIX requires the appendix regardless. NOT DONE, drafting work for the human.

## Open items for the human

1. Draft Open Science appendix (~1 page). Material in `supplementary/README.md` covers Lean tarball, build commands, axiom verification, and theorem inventory.
2. Draft Ethics Considerations appendix (~1 page). Not present in repo; needs writing. Formal-substrate paper without human subjects, but the appendix is mandatory.
3. Confirm that citing the parent `chioProgrammableSovereignty2027` (author `{Chio Project}`) and referring to "the Chio substrate" in Section 1 and Section 8 is consistent with the human's reading of USENIX Security 2027 double-blind policy. The substrate identifier is a public artifact and the citation uses a project name rather than a personal name, but the human should make the final call.
4. Register USENIX account and click Submit.

## Verification log

### make submit-check (tail)

```
Output written on paper-usenix.pdf (12 pages, 204861 bytes).
Transcript written on paper-usenix.log.
  exit=0
[submit-check] running gates against paper-usenix
[check-log] scanning paper-usenix.log
[check-log] OK
[check-bibtex] scanning paper-usenix.blg
[check-bibtex] OK
[check-pages] paper-usenix.pdf: total=12, refs start page=11, body=10 (max=13)
[check-pages] OK
[submit-check] VERDICT: PASS (paper-usenix is submission-ready)
```

### Tarball verify

```
$ tar xzf supplementary/lean-source.tar.gz   (size 41194 B)
$ cd chio-lean && lake build
... (24 jobs)
Build completed successfully (24 jobs).
lake build  11.40s user  4.84s system  141% cpu  11.480 total
```

### #print axioms

```
'Chio.Treaty.SensorAttestation.admission_predicate_separates_healthy_and_degraded_witnesses' depends on axioms: [propext, Classical.choice, Quot.sound]
'Chio.Treaty.SensorAttestation.partition_contingency_mode_iff_degraded_subset' depends on axioms: [propext]
'Chio.Treaty.SensorAttestation.healthy_attestation_required_for_destructive_admission' depends on axioms: [propext]
'Chio.Treaty.SensorAttestation.degraded_sensor_admission_requires_re_admission_witness' depends on axioms: [propext, Quot.sound]
```

### TOML / JSON parse

```
$ python3 -c "import tomllib; tomllib.loads(open('supplementary/proof-manifest.toml','rb').read().decode())"
TOML OK; top-level keys: ['manifest', 'theorems']
$ python3 -m json.tool < supplementary/theorem-inventory.json > /dev/null
JSON OK
```

### Em-dash scan

```
paper-usenix.tex clean
paper.tex clean
sections/*.tex clean
supplementary/* clean
```
