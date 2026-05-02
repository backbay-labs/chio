#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/bisect-bypass.sh [--dispatch] [--workflow ci.yml] [--out PATH]

Catalog PRs #306-#425 from the admin-merge bypass window and optionally
dispatch a workflow_dispatch probe for each merge commit through a
temporary remote branch.

Default mode is catalog-only. It writes the CSV expected by M03.P2.T2
without launching paid CI. Pass --dispatch to create probe branches,
push them, and run the selected workflow against each branch.
USAGE
}

mode="catalog"
workflow="ci.yml"
out=".planning/trajectory-3/audits/M03-bypass-bisect.csv"

while (($#)); do
  case "$1" in
    --dispatch)
      mode="dispatch"
      shift
      ;;
    --catalog-only)
      mode="catalog"
      shift
      ;;
    --workflow)
      workflow="${2:?missing workflow}"
      shift 2
      ;;
    --out)
      out="${2:?missing output path}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
mkdir -p "$(dirname "$out")"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

printf '%s\n' \
  "pr,merge_sha,merged_at,title,owning_milestone,dispatch_mode,dispatch_run_id,conclusion,notes" \
  > "$out"

for page in {1..10}; do
  gh api "repos/${repo}/pulls?state=closed&sort=updated&direction=desc&per_page=100&page=${page}" \
    --jq '.[] | select(.merged_at != null and .number >= 306 and .number <= 425) |
      [.number, .merge_commit_sha, .merged_at, .title, .html_url] | @tsv' >> "$tmp"
done

sort -n -k1,1 "$tmp" | uniq | while IFS=$'\t' read -r pr merge_sha merged_at title url; do
  milestone="$(printf '%s' "$title" | grep -oE 'M0[1-9]|M10' | head -1 || true)"
  if [[ -z "$milestone" ]]; then
    milestone="unassigned"
  fi

  dispatch_run_id=""
  conclusion="not_dispatched"
  notes="$url"

  if [[ "$mode" == "dispatch" ]]; then
    branch="m03-bisect/pr-${pr}"
    git push origin "${merge_sha}:refs/heads/${branch}"
    # The workflow_dispatch event requires a ref that resolves in the repo.
    gh workflow run "$workflow" --ref "$branch"
    sleep 2
    dispatch_run_id="$(gh run list \
      --workflow "$workflow" \
      --branch "$branch" \
      --limit 1 \
      --json databaseId \
      --jq '.[0].databaseId // empty')"
    conclusion="queued"
    notes="workflow_dispatch ${workflow} on ${branch}; source ${url}"
  fi

  title_csv="$(printf '%s' "$title" | sed 's/"/""/g')"
  notes_csv="$(printf '%s' "$notes" | sed 's/"/""/g')"
  printf '%s,%s,%s,"%s",%s,%s,%s,%s,"%s"\n' \
    "$pr" "$merge_sha" "$merged_at" "$title_csv" "$milestone" "$mode" \
    "${dispatch_run_id:-}" "$conclusion" "$notes_csv" >> "$out"
done

rows="$(($(wc -l < "$out") - 1))"
if [[ "$rows" -ne 118 ]]; then
  echo "expected 118 PR rows for #306-#425, wrote ${rows}" >&2
  exit 1
fi

echo "wrote ${rows} bypass rows to ${out}"
