# Submission-check harness for the programmable-sovereignty paper.
#
# This Makefile template is reused for papers/sensor-grounded-admission/Makefile
# (copy-edit the TARGET defaults and the submit-check recipe to point at the
# right .tex stem). The check primitives (check-log, check-bibtex, check-pages)
# are paper-agnostic and reusable as-is.
#
# Pass criteria for a submission-ready build:
#   1. pdflatex 4-pass clean (exit 0 every pass).
#   2. Zero lines beginning with "!" in the .log.
#   3. Zero "LaTeX Warning: There were undefined references" lines.
#   4. Zero "LaTeX Warning: Citation" lines.
#   5. Zero "Warning--" or error lines in the .blg.
#   6. Body-page count (pages preceding References) within the venue body-limit
#      (default 13 for USENIX Security; references are excluded).
#
# Targets:
#   build-acmart            4-pass build of paper.tex (acmart fallback).
#   build-usenix            4-pass build of paper-usenix.tex (submission target).
#   check-log TARGET=stem   Scan stem.log for fatal errors / undefined refs / citations.
#   check-bibtex TARGET=stem Scan stem.blg for warnings or errors.
#   check-pages TARGET=stem MAX=N  Fail if body-page count (pages preceding the
#                                  References heading) exceeds N. References and
#                                  pages they share are excluded; the body count
#                                  is what USENIX Security measures against the
#                                  per-cycle page limit.
#   submit-check            build-usenix + all three checks against paper-usenix.
#   submit-check-acmart     same gate against paper.tex (sanity-check fallback).
#   clean                   remove aux files but keep PDFs.

LATEX     ?= pdflatex
BIBTEX    ?= bibtex
PDFINFO   ?= pdfinfo
PDFTOTEXT ?= pdftotext
LATEXOPTS ?= -interaction=nonstopmode -halt-on-error -file-line-error

# Default body-page limit for USENIX Security.
MAX ?= 13

# Default target stem for parameterized check-* targets when not overridden.
TARGET ?= paper-usenix

.PHONY: all build-acmart build-usenix check-log check-bibtex check-pages \
        submit-check submit-check-acmart clean

all: submit-check

# ---- Build recipes ---------------------------------------------------------
#
# Four passes: latex / bibtex / latex / latex. The final pass settles cross-
# references and the bibliography. Each pdflatex pass's exit code is echoed.
# We use `set -e` style chaining so a hard failure aborts the recipe.

build-acmart:
	@echo "[build-acmart] pass 1 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper.tex && echo "  exit=0"
	@echo "[build-acmart] pass 2 (bibtex)"
	$(BIBTEX) paper && echo "  exit=0"
	@echo "[build-acmart] pass 3 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper.tex && echo "  exit=0"
	@echo "[build-acmart] pass 4 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper.tex && echo "  exit=0"

build-usenix:
	@echo "[build-usenix] pass 1 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper-usenix.tex && echo "  exit=0"
	@echo "[build-usenix] pass 2 (bibtex)"
	$(BIBTEX) paper-usenix && echo "  exit=0"
	@echo "[build-usenix] pass 3 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper-usenix.tex && echo "  exit=0"
	@echo "[build-usenix] pass 4 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper-usenix.tex && echo "  exit=0"

# ---- Gate primitives -------------------------------------------------------
#
# Each check reads a single artefact and exits non-zero on any match. The
# echoed lines name the offending content so failures are debuggable from CI
# output alone.

check-log:
	@if [ ! -f $(TARGET).log ]; then \
	  echo "[check-log] FAIL: $(TARGET).log not found"; exit 1; \
	fi
	@echo "[check-log] scanning $(TARGET).log"
	@fail=0; \
	if grep -n '^!' $(TARGET).log >/dev/null 2>&1; then \
	  echo "[check-log] FAIL: fatal '!' lines:"; \
	  grep -n '^!' $(TARGET).log; fail=1; \
	fi; \
	if grep -nE '(LaTeX|Package natbib) Warning: There were undefined (references|citations)' $(TARGET).log >/dev/null 2>&1; then \
	  echo "[check-log] FAIL: undefined references / citations:"; \
	  grep -nE '(LaTeX|Package natbib) Warning: There were undefined (references|citations)' $(TARGET).log; fail=1; \
	fi; \
	if grep -nE '(LaTeX|Package natbib) Warning: Citation' $(TARGET).log >/dev/null 2>&1; then \
	  echo "[check-log] FAIL: citation warnings:"; \
	  grep -nE '(LaTeX|Package natbib) Warning: Citation' $(TARGET).log; fail=1; \
	fi; \
	if grep -nE 'LaTeX Warning: Reference .* undefined' $(TARGET).log >/dev/null 2>&1; then \
	  echo "[check-log] FAIL: undefined cross-references:"; \
	  grep -nE 'LaTeX Warning: Reference .* undefined' $(TARGET).log; fail=1; \
	fi; \
	if [ $$fail -eq 0 ]; then echo "[check-log] OK"; fi; \
	exit $$fail

check-bibtex:
	@if [ ! -f $(TARGET).blg ]; then \
	  echo "[check-bibtex] FAIL: $(TARGET).blg not found"; exit 1; \
	fi
	@echo "[check-bibtex] scanning $(TARGET).blg"
	@fail=0; \
	if grep -n 'Warning--' $(TARGET).blg >/dev/null 2>&1; then \
	  echo "[check-bibtex] FAIL: BibTeX warnings:"; \
	  grep -n 'Warning--' $(TARGET).blg; fail=1; \
	fi; \
	if grep -nE '^(I was|---|Error|error message)' $(TARGET).blg >/dev/null 2>&1; then \
	  echo "[check-bibtex] FAIL: BibTeX error markers:"; \
	  grep -nE '^(I was|---|Error|error message)' $(TARGET).blg; fail=1; \
	fi; \
	if [ $$fail -eq 0 ]; then echo "[check-bibtex] OK"; fi; \
	exit $$fail

check-pages:
	@if [ ! -f $(TARGET).pdf ]; then \
	  echo "[check-pages] FAIL: $(TARGET).pdf not found"; exit 1; \
	fi
	@total=$$($(PDFINFO) $(TARGET).pdf | awk '/^Pages:/ {print $$2}'); \
	if [ -z "$$total" ]; then \
	  echo "[check-pages] FAIL: could not parse page count"; exit 1; \
	fi; \
	refs_page=0; \
	for p in $$(seq 1 $$total); do \
	  if $(PDFTOTEXT) -layout -f $$p -l $$p $(TARGET).pdf - 2>/dev/null \
	      | grep -qE '(^|[[:space:]]{2,})References([[:space:]]|$$)'; then \
	    refs_page=$$p; break; \
	  fi; \
	done; \
	if [ $$refs_page -eq 0 ]; then \
	  echo "[check-pages] FAIL: could not locate References heading in PDF"; \
	  exit 1; \
	fi; \
	body=$$((refs_page - 1)); \
	echo "[check-pages] $(TARGET).pdf: total=$$total, refs start page=$$refs_page, body=$$body (max=$(MAX))"; \
	if [ $$body -gt $(MAX) ]; then \
	  echo "[check-pages] FAIL: body pages $$body exceeds limit $(MAX)"; \
	  exit 1; \
	fi; \
	echo "[check-pages] OK"

# ---- Composite gates -------------------------------------------------------
#
# submit-check is the primary submission gate. It exits 0 iff every primitive
# above succeeds. submit-check-acmart is the acmart-fallback variant.

submit-check: build-usenix
	@echo "[submit-check] running gates against paper-usenix"
	@$(MAKE) --no-print-directory check-log    TARGET=paper-usenix
	@$(MAKE) --no-print-directory check-bibtex TARGET=paper-usenix
	@$(MAKE) --no-print-directory check-pages  TARGET=paper-usenix MAX=$(MAX)
	@echo "[submit-check] VERDICT: PASS (paper-usenix is submission-ready)"

submit-check-acmart: build-acmart
	@echo "[submit-check-acmart] running gates against paper"
	@$(MAKE) --no-print-directory check-log    TARGET=paper
	@$(MAKE) --no-print-directory check-bibtex TARGET=paper
	@$(MAKE) --no-print-directory check-pages  TARGET=paper MAX=$(MAX)
	@echo "[submit-check-acmart] VERDICT: PASS (acmart fallback is submission-ready)"

# ---- Housekeeping ----------------------------------------------------------

clean:
	rm -f paper.aux paper.bbl paper.blg paper.log paper.out
	rm -f paper-usenix.aux paper-usenix.bbl paper-usenix.blg paper-usenix.log paper-usenix.out
