# hello-receipt-verify

Minimal offline evidence verification example using a checked-in captured bundle.

This example does not start trust, issue capabilities, or run an app surface. It starts from an already-captured evidence package and shows how to:

- verify the package offline with `chio evidence verify`
- inspect one receipt and its capability lineage
- prove that tampering breaks verification

The package was exported from a real local `chio check` policy evaluation. It contains one signed decision and its full signed capability lineage. It records no executed file read, checkpoint, witness, or transparency publication. `trusted-signers.json` records the key selected on the generating operator host; for your own records, supply your own independently trusted keys.

## What It Demonstrates

- receipt verification from a static captured package
- local lineage inspection without any live service
- tamper detection through manifest-backed file hashes

## Files

```text
ARCHITECTURE.md
README.md
fixtures/minimal-evidence/
smoke.sh
test_verify_artifacts.py
verify_artifacts.py
```

## Run

Verify the captured package and run the tamper check:

```bash
./smoke.sh
```

Run the offline artifact verifier tests:

```bash
python3 -m unittest discover -s . -p 'test_*.py'
```

## Note

This example stops at offline verification. `chio evidence import` is intentionally stricter and requires a signed bilateral federation policy, so it belongs in a federation-focused example rather than this minimal offline verifier.

The `verify.py`, `verify.mjs`, and `verify.go` programs verify receipts using the matching public Chio SDK source. The documentation download includes those exact SDKs and package-manager setup. They require the trusted-signer APIs from this source revision; the older registry releases do not provide those APIs.
