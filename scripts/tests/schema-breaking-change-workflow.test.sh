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
grep -Fq "if scripts/classify-schema-compatibility.sh \\" "$workflow"
grep -Fq "if: always() && (steps.diff.outcome == 'success' || steps.diff.outcome == 'failure')" \
  "$workflow"
# shellcheck disable=SC2016
grep -Fq 'DIFF_OUTCOME: ${{ steps.diff.outcome }}' "$workflow"

capture_classifier_status() {
  local binary="$1"
  local status
  if SCHEMA_DIFF_BIN="$binary" \
    "$classifier" "${tmpdir}/source.json" "${tmpdir}/destination.json" "${tmpdir}/report"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$status"
}

[[ "$(capture_classifier_status "${tmpdir}/breaking")" -eq 10 ]]
[[ "$(capture_classifier_status "${tmpdir}/tool-error")" -eq 20 ]]

awk '
  $0 == "      - name: Run compatibility diff over each changed schema" {
    in_step = 1
    next
  }
  in_step && $0 == "        run: |" {
    in_run = 1
    next
  }
  in_run && /^          / {
    sub(/^          /, "")
    print
    next
  }
  in_run && /^[[:space:]]*$/ {
    print
    next
  }
  in_run {
    exit
  }
' "$workflow" >"${tmpdir}/diff-step.sh"

[[ "$(sed -n '1p' "${tmpdir}/diff-step.sh")" == "set -euo pipefail" ]]
bash -n "${tmpdir}/diff-step.sh"

awk '
  $0 == "          script: |" {
    in_script = 1
    next
  }
  in_script && /^            / {
    sub(/^            /, "")
    print
    next
  }
  in_script && /^[[:space:]]*$/ {
    print
    next
  }
  in_script {
    exit
  }
' "$workflow" >"${tmpdir}/advisory.js"

test -s "${tmpdir}/advisory.js"

node - "${tmpdir}/advisory.js" <<'JS'
const assert = require('node:assert/strict');
const fs = require('node:fs');

const source = fs.readFileSync(process.argv[2], 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const executeAdvisory = new AsyncFunction('github', 'context', 'core', source);
const marker = '<!-- chio:schema-breaking-change -->';
const envKeys = [
  'SUMMARY_MD',
  'BREAKING_COUNT',
  'TOOL_ERROR_COUNT',
  'DIFF_OUTCOME',
];

async function runAdvisory({
  outcome,
  breakingCount,
  toolErrorCount,
  summary,
  prior = false,
}) {
  for (const key of envKeys) {
    delete process.env[key];
  }
  if (outcome !== undefined) process.env.DIFF_OUTCOME = outcome;
  if (breakingCount !== undefined) process.env.BREAKING_COUNT = breakingCount;
  if (toolErrorCount !== undefined) process.env.TOOL_ERROR_COUNT = toolErrorCount;
  if (summary !== undefined) process.env.SUMMARY_MD = summary;

  const writes = [];
  const infos = [];
  const warnings = [];
  const comments = prior
    ? [{ id: 71, body: `${marker}\nprevious advisory` }]
    : [];
  const issues = {
    listComments: async () => {
      throw new Error('listComments must be called through paginate');
    },
    updateComment: async args => {
      writes.push({ kind: 'update', ...args });
    },
    createComment: async args => {
      writes.push({ kind: 'create', ...args });
    },
  };
  const github = {
    rest: { issues },
    paginate: async (operation, args) => {
      assert.equal(operation, issues.listComments);
      assert.equal(args.issue_number, 1031);
      return comments;
    },
  };
  const context = {
    workflow: 'schema-breaking-change',
    runId: 4001,
    repo: { owner: 'bb-connor', repo: 'arc' },
    payload: {
      pull_request: {
        number: 1031,
        base: { ref: 'main' },
      },
    },
  };
  const core = {
    info: message => infos.push(message),
    warning: message => warnings.push(message),
  };

  await executeAdvisory(github, context, core);
  return { writes, infos, warnings };
}

function onlyBody(result, kind) {
  assert.equal(result.writes.length, 1);
  assert.equal(result.writes[0].kind, kind);
  return result.writes[0].body;
}

(async () => {
  const cleanWithoutSticky = await runAdvisory({
    outcome: 'success',
    breakingCount: '0',
    toolErrorCount: '0',
    summary: '',
  });
  assert.equal(cleanWithoutSticky.writes.length, 0);
  assert.match(cleanWithoutSticky.infos[0], /nothing to post/);

  const cleanWithSticky = await runAdvisory({
    outcome: 'success',
    breakingCount: '0',
    toolErrorCount: '0',
    summary: '',
    prior: true,
  });
  const cleanBody = onlyBody(cleanWithSticky, 'update');
  assert.match(cleanBody, /reports no breaking changes/);
  assert.doesNotMatch(cleanBody, /Unchecked result/);

  const breaking = await runAdvisory({
    outcome: 'success',
    breakingCount: '1',
    toolErrorCount: '0',
    summary: '- `spec/schemas/example.json`: BREAKING. Required field.',
  });
  const breakingBody = onlyBody(breaking, 'create');
  assert.match(breakingBody, /flagged 1 schema/);
  assert.match(breakingBody, /Required field/);
  assert.doesNotMatch(breakingBody, /Unchecked result/);

  const mixedFailure = await runAdvisory({
    outcome: 'failure',
    breakingCount: '1',
    toolErrorCount: '2',
    summary: '- `spec/schemas/example.json`: BREAKING. Required field.',
    prior: true,
  });
  const mixedBody = onlyBody(mixedFailure, 'update');
  assert.match(mixedBody, /Required field/);
  assert.match(mixedBody, /failed for 2 schema/);
  assert.match(mixedBody, /Unchecked result/);
  assert.doesNotMatch(mixedBody, /reports no breaking changes/);

  const failedWithoutOutputs = await runAdvisory({
    outcome: 'failure',
    prior: true,
  });
  const failedWithoutOutputsBody = onlyBody(failedWithoutOutputs, 'update');
  assert.match(failedWithoutOutputsBody, /did not emit a complete set/);
  assert.match(failedWithoutOutputsBody, /this run is not an all-clear/);
  assert.doesNotMatch(failedWithoutOutputsBody, /reports no breaking changes/);

  const successWithoutOutputs = await runAdvisory({
    outcome: 'success',
    breakingCount: '0',
    prior: true,
  });
  const successWithoutOutputsBody = onlyBody(successWithoutOutputs, 'update');
  assert.match(successWithoutOutputsBody, /did not emit a complete set/);
  assert.match(successWithoutOutputsBody, /Unchecked result/);
  assert.doesNotMatch(successWithoutOutputsBody, /reports no breaking changes/);

  const failedWithCompleteZeroOutputs = await runAdvisory({
    outcome: 'failure',
    breakingCount: '0',
    toolErrorCount: '0',
    summary: '',
    prior: true,
  });
  const failedWithCompleteZeroBody =
    onlyBody(failedWithCompleteZeroOutputs, 'update');
  assert.match(failedWithCompleteZeroBody, /workflow outcome `failure`/);
  assert.match(failedWithCompleteZeroBody, /Unchecked result/);
  assert.doesNotMatch(failedWithCompleteZeroBody, /reports no breaking changes/);

  const breakingWithoutSummary = await runAdvisory({
    outcome: 'success',
    breakingCount: '1',
    toolErrorCount: '0',
    summary: '',
    prior: true,
  });
  const breakingWithoutSummaryBody =
    onlyBody(breakingWithoutSummary, 'update');
  assert.match(breakingWithoutSummaryBody, /flagged 1 schema/);
  assert.match(breakingWithoutSummaryBody, /did not emit a complete set/);
  assert.match(breakingWithoutSummaryBody, /Unchecked result/);
  assert.doesNotMatch(breakingWithoutSummaryBody, /reports no breaking changes/);

  const malformedCount = await runAdvisory({
    outcome: 'success',
    breakingCount: '0junk',
    toolErrorCount: '0',
    summary: '',
    prior: true,
  });
  const malformedCountBody = onlyBody(malformedCount, 'update');
  assert.match(malformedCountBody, /did not emit a complete set/);
  assert.match(malformedCountBody, /Unchecked result/);
  assert.doesNotMatch(malformedCountBody, /reports no breaking changes/);

  const failedWithoutSticky = await runAdvisory({
    outcome: 'failure',
  });
  const failedWithoutStickyBody = onlyBody(failedWithoutSticky, 'create');
  assert.match(failedWithoutStickyBody, /Unchecked result/);
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
JS

echo "schema-breaking-change-workflow.test.sh: compatibility and advisory behavior passed"
