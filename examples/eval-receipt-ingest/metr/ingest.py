#!/usr/bin/env python3
"""Package a METR-style eval export into a Chio receipt bundle."""

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = ROOT / "crates/chio-eval-receipt/tests/fixtures"
OUTPUT = ROOT / "examples/eval-receipt-ingest/metr/out/metr-sample-bundle.json"

SCENARIOS = (
    ("capability-subset-001-read-exact", "capability_subset", "allow"),
    ("revocation-propagation-001-active-read", "revocation_propagation", "allow"),
    ("replay-verdict-001-fresh-read", "replay_verdict", "allow"),
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def receipt_entry(index, scenario_id, category, verdict):
    payload_path = FIXTURE_DIR / f"{scenario_id}.receipt.json"
    payload = payload_path.read_text(encoding="utf-8")
    return {
        "scenario_id": scenario_id,
        "category": category,
        "verdict": verdict,
        "receipt_payload": payload,
        "receipt_sha256": sha256_text(payload),
        "evidence": {"trace_id": f"metr-vivaria-trace-{index:03d}", "sample_id": f"metr-sample-{index:03d}"},
    }


def canonical_payload_without_signatures(bundle):
    unsigned = dict(bundle)
    unsigned.pop("signatures", None)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"))


def build_bundle():
    bundle = {
        "schema": "chio.eval-report.bundle.v1",
        "bundle_id": "urn:chio:eval-bundle:metr:sample-v1",
        "created_at": "2026-05-02T00:00:00Z",
        "producer": {
            "name": "Chio",
            "repository": "https://github.com/backbay-labs/chio",
            "commit": "v0.1.0",
            "workflow_run_url": "https://github.com/backbay-labs/chio/actions/runs/25246581763",
        },
        "eval_run": {
            "run_id": "metr-vivaria-export-v1",
            "partner": "METR",
            "partner_slug": "metr",
            "pipeline": "vivaria-trace-postprocess",
            "pipeline_language": "python",
            "model_under_eval": "partner-model",
            "scorer_name": "tool-use-rubric",
            "scorer_version": "v1",
        },
        "corpus": {
            "name": "chio-verdict-matrix",
            "scenario_count": 48,
            "corpus_sha256": "47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f",
            "manifest_path": "crates/chio-conformance/verdict_matrix/manifest.toml",
        },
        "receipts": [
            receipt_entry(index, scenario_id, category, verdict)
            for index, (scenario_id, category, verdict) in enumerate(SCENARIOS, start=1)
        ],
        "partner_review": {"feedback_ref": "METR pair-run 2026-05-02", "review_window_days": 7, "reviewer_role": "partner technical reviewer", "disposition": "accepted-with-notes"},
        "signatures": [],
    }
    signature = sha256_text(canonical_payload_without_signatures(bundle))
    bundle["signatures"] = [{"kind": "test-sha256", "key_id": "local-test-cosign-oidc", "signature": signature, "signed_payload": "bundle_without_signatures:rfc8785"}]
    return bundle


def verify_bundle(path):
    subprocess.run(
        ["cargo", "run", "-p", "chio-eval-receipt", "--bin", "chio-eval-receipt", "--", "verify-fixture", str(path)],
        cwd=ROOT,
        check=True,
    )


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(build_bundle(), indent=2) + "\n", encoding="utf-8")
    verify_bundle(OUTPUT)
    print(f"wrote and verified {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
