#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


EXPECTED = [
    {
        "id": "revocation-visibility-bypass",
        "source": "kernel-runtime",
        "fault": "revocation store reports a committed revoke but hides it at admission",
        "expected_rejection": "NoAllowAfterRevoke",
        "gate": "./scripts/check-receipt-trace.sh",
    },
    {
        "id": "duplicate-receipt-time",
        "source": "kernel-runtime-observer-mutation",
        "fault": "the observer maps the second real receipt append to the first receipt time",
        "expected_rejection": "MonotoneLog",
        "gate": "./scripts/check-receipt-trace.sh",
    },
    {
        "id": "delegation-depth-above-limit",
        "source": "kernel-runtime-observer-mutation",
        "fault": "the observer maps a real admitted delegation above the signed kernel depth limit",
        "expected_rejection": "AttenuationPreserving",
        "gate": "./scripts/check-receipt-trace.sh",
    },
    {
        "id": "future-revocation-epoch",
        "source": "kernel-runtime-observer-mutation",
        "fault": "the observer maps a real committed revocation to an epoch beyond the model clock",
        "expected_rejection": "RevocationFreshness",
        "gate": "./scripts/check-receipt-trace.sh",
    },
    {
        "id": "dropped-admission-callback",
        "source": "kernel-runtime",
        "fault": "the observer drops a real admission callback before the receipt append",
        "expected_rejection": "runtime callback completeness",
        "gate": "cargo test -p chio-conformance --lib runtime_trace_refuses_a_dropped_admission_callback",
    },
]
FORMAL_REJECTIONS = {
    "NoAllowAfterRevoke",
    "MonotoneLog",
    "AttenuationPreserving",
    "RevocationFreshness",
}


def parse_report_arg(raw: str) -> tuple[str, Path]:
    name, separator, path = raw.partition("=")
    if not separator or name not in FORMAL_REJECTIONS or not path:
        raise argparse.ArgumentTypeError("report must be INVARIANT=PATH")
    return name, Path(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--report", required=True, action="append", type=parse_report_arg)
    args = parser.parse_args()

    registry = tomllib.loads(args.registry.read_text(encoding="utf-8"))
    if registry.get("schema") != "chio.runtime-trace-negative.v1":
        raise SystemExit("receipt-trace-negative: registry schema is invalid")
    if registry.get("case") != EXPECTED:
        raise SystemExit("receipt-trace-negative: registry entries are not exact")
    registered = {
        case["expected_rejection"]
        for case in EXPECTED
        if case["expected_rejection"] in FORMAL_REJECTIONS
    }
    if registered != FORMAL_REJECTIONS:
        raise SystemExit("receipt-trace-negative: formal invariant coverage is incomplete")

    reports = dict(args.report)
    if set(reports) != FORMAL_REJECTIONS or len(args.report) != len(FORMAL_REJECTIONS):
        raise SystemExit("receipt-trace-negative: report set is not exact")
    for expected, path in reports.items():
        report = json.loads(path.read_text(encoding="utf-8"))
        divergence = report.get("divergence", {})
        if report.get("schema") != "chio.trace-validation.v1":
            raise SystemExit(f"receipt-trace-negative: {expected} report schema is invalid")
        if report.get("status") != "failed":
            raise SystemExit(f"receipt-trace-negative: {expected} mutation was not rejected")
        if divergence.get("failedConjunct") != expected:
            raise SystemExit(f"receipt-trace-negative: {expected} hit the wrong invariant")
        if divergence.get("apalacheEvaluation", {}).get(expected) is not False:
            raise SystemExit(f"receipt-trace-negative: {expected} lacks an Apalache witness")

    native_source = Path("crates/tooling/chio-conformance/src/native_suite.rs").read_text(
        encoding="utf-8"
    )
    trace_source = Path("crates/tooling/chio-trace-validate/src/capture.rs").read_text(
        encoding="utf-8"
    )
    for symbol, source in (
        ("BlindRevocationStore", native_source),
        ("runtime_trace_refuses_a_dropped_admission_callback", native_source),
        ("AdmissionDroppingObserver", native_source),
        ("DuplicateReceiptTime", trace_source),
        ("DepthAboveLimit", trace_source),
        ("FutureRevocationEpoch", trace_source),
    ):
        if symbol not in source:
            raise SystemExit(f"receipt-trace-negative: missing calibration symbol {symbol}")


if __name__ == "__main__":
    main()
