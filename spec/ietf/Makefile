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

# WeasyPrint, the PDF backend of xml2rfc, finds Homebrew's Pango through this
# path on macOS.
ifeq ($(shell uname -s),Darwin)
export DYLD_FALLBACK_LIBRARY_PATH ?= /opt/homebrew/lib
endif

.PHONY: all vectors check clean
all: vectors $(OUTDIR)/$(OUT).xml $(OUTDIR)/$(OUT).prepped.xml $(OUTDIR)/$(OUT).txt $(OUTDIR)/$(OUT).pdf

vectors:
	$(PYTHON) tools/render_vectors.py --vectors $(VECTORS) --out generated

$(OUTDIR)/$(OUT).raw.xml: $(SRC) $(wildcard generated/*.md)
	$(KRAMDOWN) $(SRC) | sed -E 's/<\?line -?[0-9]+\?>//g' > $@

$(OUTDIR)/$(OUT).xml: $(OUTDIR)/$(OUT).raw.xml
	$(XML2RFC) --v3 --quiet --expand $< -o $@

$(OUTDIR)/$(OUT).prepped.xml: $(OUTDIR)/$(OUT).xml
	$(XML2RFC) --v3 --quiet --preptool $< -o $@

$(OUTDIR)/$(OUT).txt: $(OUTDIR)/$(OUT).xml
	$(XML2RFC) --v3 --quiet --text $< -o $@

$(OUTDIR)/$(OUT).pdf: $(OUTDIR)/$(OUT).xml
	$(XML2RFC) --v3 --quiet --pdf $< -o $@

check:
	./tools/check.sh

clean:
	rm -f $(OUTDIR)/$(OUT).raw.xml
