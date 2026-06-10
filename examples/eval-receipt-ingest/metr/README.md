# METR Eval-Receipt Ingest Sample

This sample mirrors the METR vivaria trace post-processing handoff from
`crates/sdk/chio-eval-receipt/EXPORT-CONTRACT.md`. It packages three
verdict-matrix receipt fixtures into `chio.eval-report.bundle.v1`, signs
the bundle with the local test signature used by the reference verifier,
and round-trips the output through `chio-eval-receipt verify-fixture`.

Run from the repository root:

```bash
python3 examples/eval-receipt-ingest/metr/ingest.py
```

The script writes `examples/eval-receipt-ingest/metr/out/metr-sample-bundle.json`
and exits non-zero if the Rust verifier rejects the bundle.
