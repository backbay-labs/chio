#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' "usage: shadow-capture.sh --sidecar-url URL --output FILE [--duration-seconds N]"
}

SIDECAR_URL=""
OUTPUT=""
DURATION_SECONDS="86400"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --sidecar-url)
      shift
      SIDECAR_URL="${1:-}"
      ;;
    --output)
      shift
      OUTPUT="${1:-}"
      ;;
    --duration-seconds)
      shift
      DURATION_SECONDS="${1:-}"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'shadow-capture: unknown argument %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ -z "$SIDECAR_URL" ] || [ -z "$OUTPUT" ]; then
  usage >&2
  exit 2
fi

if [[ "$SIDECAR_URL" == *\"* || "$SIDECAR_URL" == *\\* || "$SIDECAR_URL" == *[[:cntrl:]]* ]]; then
  printf 'shadow-capture: sidecar url contains characters unsafe for JSON manifest\n' >&2
  exit 2
fi

case "$DURATION_SECONDS" in
  ''|*[!0-9]*)
    printf 'shadow-capture: duration must be an integer number of seconds\n' >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$OUTPUT")"

cat > "$OUTPUT" <<JSON
{
  "capture": "healthcare-design-partner-shadow",
  "mode": "read-only tee",
  "sidecar_url": "$SIDECAR_URL",
  "duration_seconds": $DURATION_SECONDS,
  "topology": "design-partner app -> Chio sidecar -> wrapped MCP HTTP server",
  "contains_phi": false,
  "notes": [
    "Capture only metadata needed for capacity replay.",
    "Do not persist request bodies, response bodies, patient identifiers, or clinical free text.",
    "Use this output as the baseline input for 1x, 2x, and 5x replay."
  ]
}
JSON

printf 'shadow-capture: wrote design-partner tee manifest to %s\n' "$OUTPUT"
