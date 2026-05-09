#!/usr/bin/env bash
# Close-bar snapshot-frozen gate.
#
# The companion `check-close-bar-tracker.sh` gate compares the tracker
# against the in-tree snapshot at `audits/evidence/close-bar-snapshot.json`
# to refuse regressions. That gate is bypassable: a PR could downgrade a
# row in the tracker (DONE -> PARTIAL/NONE) AND simultaneously edit the
# snapshot to match, and the in-tree comparison would still pass.
#
# This gate closes that surface by treating the version of the snapshot
# on `origin/main` (or, in tests, an explicit base path) as the source
# of truth for "highest-rank-ever-seen" per row. Any PR head that
# downgrades a row's bucket (DONE -> PARTIAL, DONE -> NONE, PARTIAL -> NONE)
# relative to the base snapshot is rejected, even if the head snapshot
# itself was edited to match.
#
# Failure modes (any one fails the gate):
#   1. base snapshot cannot be loaded;
#   2. head snapshot cannot be loaded;
#   3. any row's bucket regresses on the head tracker relative to the
#      base snapshot (DONE -> PARTIAL/NONE, PARTIAL -> NONE).
#
# Environment overrides (used by integration tests):
#   CHIO_CLOSE_BAR_TRACKER         path to the head tracker markdown
#   CHIO_CLOSE_BAR_BASE_SNAPSHOT   path to a base snapshot JSON (overrides
#                                  the `git show origin/main:...` lookup)
#   CHIO_CLOSE_BAR_BASE_REF        git ref for the base snapshot when
#                                  CHIO_CLOSE_BAR_BASE_SNAPSHOT is unset
#                                  (default: origin/main)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

default_tracker() {
    find "$REPO_ROOT/.planning" -path '*/closeout/CLOSE-BAR-TRACKER.md' -type f -print 2>/dev/null \
        | LC_ALL=C sort \
        | tail -n 1
}

TRACKER="${CHIO_CLOSE_BAR_TRACKER:-$(default_tracker)}"
BASE_REF="${CHIO_CLOSE_BAR_BASE_REF:-origin/main}"
SNAPSHOT_REL="audits/evidence/close-bar-snapshot.json"

if [[ ! -f "$TRACKER" ]]; then
    echo "ERROR: tracker not found: $TRACKER" >&2
    exit 1
fi

# Materialise the base snapshot. Prefer the explicit override (used by
# the integration tests); otherwise read from the git ref.
BASE_SNAPSHOT_TMP=""
cleanup() {
    if [[ -n "$BASE_SNAPSHOT_TMP" && -f "$BASE_SNAPSHOT_TMP" ]]; then
        rm -f "$BASE_SNAPSHOT_TMP"
    fi
}
trap cleanup EXIT

if [[ -n "${CHIO_CLOSE_BAR_BASE_SNAPSHOT:-}" ]]; then
    BASE_SNAPSHOT="$CHIO_CLOSE_BAR_BASE_SNAPSHOT"
    if [[ ! -f "$BASE_SNAPSHOT" ]]; then
        echo "ERROR: base snapshot not found: $BASE_SNAPSHOT" >&2
        exit 1
    fi
else
    BASE_SNAPSHOT_TMP="$(mktemp -t close-bar-base.XXXXXX.json)"
    if ! git -C "$REPO_ROOT" show "$BASE_REF:$SNAPSHOT_REL" > "$BASE_SNAPSHOT_TMP" 2>/dev/null; then
        echo "ERROR: could not load $SNAPSHOT_REL from $BASE_REF; ensure $BASE_REF is fetched" >&2
        exit 1
    fi
    BASE_SNAPSHOT="$BASE_SNAPSHOT_TMP"
fi

python3 - "$TRACKER" "$BASE_SNAPSHOT" "$BASE_REF" <<'PY'
import json
import sys

tracker_path, base_snapshot_path, base_ref = sys.argv[1:4]

BUCKET_RANK = {"NONE": 0, "PARTIAL": 1, "DONE": 2}


def parse_tracker(text):
    rows = []
    in_table = False
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells:
            continue
        if cells[0] in ("ID",):
            in_table = True
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue
        if not in_table:
            continue
        if len(cells) < 8:
            continue
        rows.append({"id": cells[0], "bucket": cells[2]})
    return rows


with open(tracker_path, "r", encoding="utf-8") as fh:
    head_rows = parse_tracker(fh.read())

with open(base_snapshot_path, "r", encoding="utf-8") as fh:
    base_doc = json.load(fh)
base_rows = {r["id"]: r for r in base_doc.get("rows", [])}

errors = []
for r in head_rows:
    base = base_rows.get(r["id"])
    if base is None:
        continue
    head_rank = BUCKET_RANK.get(r["bucket"], -1)
    base_rank = BUCKET_RANK.get(base["bucket"], -1)
    if head_rank < base_rank:
        errors.append(
            f"{r['id']}: head bucket {r['bucket']!r} regresses against {base_ref} bucket {base['bucket']!r}"
        )

if errors:
    print(
        f"close-bar-snapshot-frozen gate: FAIL ({len(errors)} regression(s) vs {base_ref})",
        file=sys.stderr,
    )
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(len(errors))

print(f"close-bar-snapshot-frozen gate: PASS (no regressions vs {base_ref})")
print(f"  head rows compared: {len(head_rows)}")
print(f"  base rows known:    {len(base_rows)}")
sys.exit(0)
PY
