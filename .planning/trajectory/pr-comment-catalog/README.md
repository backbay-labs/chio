# Trajectory PR Comment Catalog

Generated on 2026-04-27 for `bb-connor/arc`. Refreshes the earlier 2026-04-26 catalog with the post-#86 wave (PRs `#87`-`#140`) and re-checks resolved/unresolved state across the whole range.

Source scope: PRs `#13` through `#140` (128 pull requests).

## Totals

- PRs cataloged: `128`
- Issue comments: `30`
- Review submissions: `187`
- Review threads: `281`
- Currently unresolved review threads: `232`
- Outdated review threads: `49`

## Files

- `PR_INDEX.md` lists every catalogued PR with comment and review-thread counts.
- `ACTION_ITEMS.md` lists every currently unresolved review thread, grouped by PR, with file/line, author, link, and a ~200-char snippet of the first comment so the action can be triaged without leaving the file.
- `raw/per-pr/pr-<NUM>.json` is the full GraphQL response per PR; `raw/fetch_pr.sh` re-fetches a single PR; `raw/build_catalog.py` regenerates the markdown from the per-PR JSON snapshots.

## Notes

GitHub review-thread state was fetched through GraphQL because flat REST review-comment endpoints do not preserve resolved/unresolved state. The first-comment body is included verbatim (truncated) for triage; GitHub remains the source of truth for full thread history and any follow-up replies beyond the snippet.

## Next step

Per-thread cleanup pass: for each row in `ACTION_ITEMS.md`, decide (a) resolve as won't-fix with explanation, (b) resolve as already-fixed, or (c) author a follow-up PR.
