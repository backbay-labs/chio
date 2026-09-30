#!/usr/bin/env python3
"""Fail on any idnits error, and on any warning that is not an accepted exception.

Each accepted code carries the reason it is accepted. Nothing else is waived.
"""
import json
import sys

ACCEPTED_WARNINGS = {
    # The source carries the planned upload date until the day of submission.
    "DOC_DATE_IN_FUTURE": "the upload date is set ahead of submission",
}

report = json.load(open(sys.argv[1]))
nits = report.get("nits", [])
failures = []
for nit in nits:
    severity = nit.get("severity", "")
    code = nit.get("code", "")
    line = f"{severity}: {code}: {nit.get('desc', '')}"
    if "Error" in severity:
        failures.append(line)
    elif "Warning" in severity and code not in ACCEPTED_WARNINGS:
        failures.append(line)
    else:
        print(f"idnits (accepted): {line}")
for line in failures:
    print(f"idnits: {line}", file=sys.stderr)
print(f"idnits: {report.get('nitsBySeverity')}")
sys.exit(1 if failures else 0)
