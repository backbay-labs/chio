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
targets="$tmp/$out.xml $tmp/$out.prepped.xml $tmp/$out.txt"
[ "${CHECK_PDF:-0}" = 1 ] && targets="$targets $tmp/$out.pdf"
make --no-print-directory OUTDIR="$tmp" $targets >/dev/null

status=0
for ext in xml txt; do
  if ! cmp -s "$out.$ext" "$tmp/$out.$ext"; then
    echo "check: $out.$ext differs from a fresh build; run make" >&2
    status=1
  fi
done
normalize() { sed -E 's/prepTime="[^"]*"/prepTime=""/' "$1"; }
if ! normalize "$out.prepped.xml" | cmp -s - "$tmp/$out.prepped.norm" 2>/dev/null; then
  normalize "$tmp/$out.prepped.xml" > "$tmp/$out.prepped.norm"
  if ! normalize "$out.prepped.xml" | cmp -s - "$tmp/$out.prepped.norm"; then
    echo "check: $out.prepped.xml differs from a fresh build; run make" >&2
    status=1
  fi
fi
# The PDF embeds a creation time and depends on installed fonts, so its text
# is compared only on request (CHECK_PDF=1), on a machine with the Noto and
# Roboto Mono fonts xml2rfc expects.
if [ "${CHECK_PDF:-0}" = 1 ]; then
  pdftotext -layout "$out.pdf" "$tmp/committed.pdf.txt"
  pdftotext -layout "$tmp/$out.pdf" "$tmp/fresh.pdf.txt"
  if ! cmp -s "$tmp/committed.pdf.txt" "$tmp/fresh.pdf.txt"; then
    echo "check: $out.pdf text differs from a fresh build; run make" >&2
    status=1
  fi
fi

if awk 'length > 72 { found = 1 } END { exit !found }' "$out.txt"; then
  echo "check: $out.txt has lines longer than 72 characters" >&2
  status=1
fi

if command -v idnits >/dev/null 2>&1; then
  idnits --mode submission --no-progress --output json "$out.xml" > "$tmp/idnits.json" 2>/dev/null || true
  python3 tools/idnits_gate.py "$tmp/idnits.json" || status=1
else
  echo "check: idnits is not installed (npm install -g @ietf-tools/idnits)" >&2
  status=1
fi
exit $status
