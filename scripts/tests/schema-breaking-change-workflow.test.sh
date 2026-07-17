#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
classifier="${repo_root}/scripts/classify-schema-compatibility.sh"
workflow="${repo_root}/.github/workflows/schema-breaking-change.yml"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat >"${tmpdir}/source.json" <<'JSON'
{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}
JSON
cp "${tmpdir}/source.json" "${tmpdir}/destination.json"

cat >"${tmpdir}/compatible" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
grep -Fq 'draft/2020-12/schema' "$1"
grep -Fq 'draft/2020-12/schema' "$2"
echo "compatible"
SH
cat >"${tmpdir}/breaking" <<'SH'
#!/usr/bin/env bash
echo "The schema is not backward compatible. Difference includes a required property." >&2
exit 1
SH
cat >"${tmpdir}/tool-error" <<'SH'
#!/usr/bin/env bash
echo "schema parser crashed" >&2
exit 1
SH
chmod +x "${tmpdir}/compatible" "${tmpdir}/breaking" "${tmpdir}/tool-error"

SCHEMA_DIFF_BIN="${tmpdir}/compatible" \
  "$classifier" "${tmpdir}/source.json" "${tmpdir}/destination.json" "${tmpdir}/report"
grep -Fq "compatible" "${tmpdir}/report"

set +e
SCHEMA_DIFF_BIN="${tmpdir}/breaking" \
  "$classifier" "${tmpdir}/source.json" "${tmpdir}/destination.json" "${tmpdir}/report"
status=$?
set -e
[[ $status -eq 10 ]]
grep -Fq "not backward compatible" "${tmpdir}/report"

set +e
SCHEMA_DIFF_BIN="${tmpdir}/tool-error" \
  "$classifier" "${tmpdir}/source.json" "${tmpdir}/destination.json" "${tmpdir}/report"
status=$?
set -e
[[ $status -eq 20 ]]
grep -Fq "schema compatibility tool failed" "${tmpdir}/report"
grep -Fq "schema parser crashed" "${tmpdir}/report"

grep -Fq "json-schema-diff-validator@0.4.2" "$workflow"
grep -Fq "scripts/classify-schema-compatibility.sh" "$workflow"
grep -Fq "tool_error_count" "$workflow"

echo "schema-breaking-change-workflow.test.sh: compatibility classification passed"
