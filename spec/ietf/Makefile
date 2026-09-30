# Build the Chio Protocol Internet-Draft from its kramdown-rfc source.
#
#   make          regenerate every committed rendering from the source
#   make check    regenerate into a temporary directory, compare with the
#                 committed renderings, check the generated appendices, and
#                 run idnits
#
# Tools: kramdown-rfc (Ruby gem), xml2rfc with its PDF extra, idnits, python3.

DRAFT   := draft-whelan-chio-protocol
REV     := 00
SRC     := $(DRAFT).md
OUT     := $(DRAFT)-$(REV)
OUTDIR  ?= .
VECTORS ?= ../../tests/bindings/vectors

KRAMDOWN ?= kramdown-rfc
XML2RFC  ?= xml2rfc
IDNITS   ?= idnits
PYTHON   ?= python3

# tools/bin/aasvg adds --compatible to every aasvg run so figures meet the
# RFC 7996 SVG profile.
export PATH := $(CURDIR)/tools/bin:$(PATH)

# Use the same licensed fonts and fallback glyphs on every build host.
export FONTCONFIG_FILE := $(CURDIR)/tools/fonts/fonts.conf

# WeasyPrint, the PDF backend of xml2rfc, finds Homebrew's Pango through this
# path on macOS.
ifeq ($(shell uname -s),Darwin)
export DYLD_FALLBACK_LIBRARY_PATH ?= /opt/homebrew/lib
endif

.DELETE_ON_ERROR:
.PHONY: all vectors check clean
all: vectors $(OUTDIR)/$(OUT).xml $(OUTDIR)/$(OUT).prepped.xml $(OUTDIR)/$(OUT).txt $(OUTDIR)/$(OUT).pdf

vectors:
	$(PYTHON) tools/render_vectors.py --vectors $(VECTORS) --out generated

$(OUTDIR)/$(OUT).raw.xml: $(SRC) Makefile tools/normalize_xml.py $(wildcard generated/*.md) | vectors
	$(KRAMDOWN) $(SRC) > $@.tmp || { draft_status=$$?; rm -f $@.tmp; exit $$draft_status; }
	$(PYTHON) tools/normalize_xml.py $@.tmp $@
	rm -f $@.tmp
	$(PYTHON) tools/check_xml.py $@

$(OUTDIR)/$(OUT).v3.xml: $(OUTDIR)/$(OUT).raw.xml
	$(XML2RFC) --v2v3 $< -o $@.tmp
	$(PYTHON) tools/normalize_xml.py $@.tmp $@
	rm -f $@.tmp

$(OUTDIR)/$(OUT).xml: $(OUTDIR)/$(OUT).v3.xml
	$(XML2RFC) --v3 --expand $< -o $@.tmp
	$(PYTHON) tools/normalize_xml.py $@.tmp $@
	rm -f $@.tmp
	$(PYTHON) tools/check_xml.py $@

$(OUTDIR)/$(OUT).prepped.xml: $(OUTDIR)/$(OUT).xml
	$(XML2RFC) --v3 --preptool $< -o $@

$(OUTDIR)/$(OUT).txt: $(OUTDIR)/$(OUT).xml
	$(XML2RFC) --v3 --text $< -o $@

$(OUTDIR)/$(OUT).pdf: $(OUTDIR)/$(OUT).xml $(wildcard tools/fonts/*)
	$(XML2RFC) --v3 --pdf $< -o $@

check:
	./tools/check.sh

clean:
	rm -f $(OUTDIR)/$(OUT).raw.xml $(OUTDIR)/$(OUT).v3.xml
