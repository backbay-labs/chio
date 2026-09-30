#!/bin/sh
# Regenerate the draft into a temporary directory and compare the result with
# the committed renderings. Fails on any difference, on a stale generated
# appendix, and on any idnits error or warning.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$here"
out=draft-whelan-chio-protocol-00

python3 tools/render_vectors.py --vectors ../../tests/bindings/vectors --out generated --check
python3 tools/test_render_vectors.py
python3 tools/test_build_gates.py
make --no-print-directory OUTDIR="$tmp" all >"$tmp/build.log" 2>&1 || {
  cat "$tmp/build.log" >&2
  exit 1
}
if rg -i '^.*(Warning:|Error:)' "$tmp/build.log"; then
  echo 'check: xml2rfc emitted a warning or error' >&2
  exit 1
else
  draft_scan_status=$?
  if [ "$draft_scan_status" -ne 1 ]; then
    echo 'check: unable to scan writer diagnostics' >&2
    exit 1
  fi
fi
python3 tools/check_xml.py "$out.xml" "$tmp/$out.xml"

status=0
for ext in xml txt; do
  if ! cmp -s "$out.$ext" "$tmp/$out.$ext"; then
    echo "check: $out.$ext differs from a fresh build; run make" >&2
    status=1
  fi
done
normalize() { sed -E 's/prepTime="[^"]*"/prepTime=""/' "$1"; }
normalize "$tmp/$out.prepped.xml" > "$tmp/$out.prepped.norm"
if ! normalize "$out.prepped.xml" | cmp -s - "$tmp/$out.prepped.norm"; then
  echo "check: $out.prepped.xml differs from a fresh build; run make" >&2
  status=1
fi
# The PDF embeds a creation time, so compare its extracted text. Reproducible
# layout uses the pinned fonts selected by Makefile's FONTCONFIG_FILE.
if command -v pdftotext >/dev/null 2>&1; then
  pdftotext -layout "$out.pdf" "$tmp/committed.pdf.txt"
  pdftotext -layout "$tmp/$out.pdf" "$tmp/fresh.pdf.txt"
  if ! cmp -s "$tmp/committed.pdf.txt" "$tmp/fresh.pdf.txt"; then
    echo "check: $out.pdf text differs from a fresh build; run make" >&2
    status=1
  fi
else
  echo 'check: pdftotext is required to verify the PDF' >&2
  status=1
fi

if awk 'length > 72 { found = 1 } END { exit !found }' "$out.txt"; then
  echo "check: $out.txt has lines longer than 72 characters" >&2
  status=1
fi

if command -v idnits >/dev/null 2>&1; then
  if idnits --mode submission --no-progress --output json "$out.xml" > "$tmp/idnits.json" 2> "$tmp/idnits.stderr"; then
    python3 tools/idnits_gate.py "$tmp/idnits.json" || status=1
  else
    cat "$tmp/idnits.stderr" >&2
    echo "check: idnits did not complete successfully" >&2
    status=1
  fi
else
  echo "check: idnits is not installed (npm install -g @ietf-tools/idnits)" >&2
  status=1
fi
exit $status
