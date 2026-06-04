# hello-trust-control

Minimal trust-plane and offline evidence example with no app surface in the middle.

This example teaches the control surfaces directly:

- start `chio trust serve`
- issue a capability from the trust-control service
- materialize the capability token
- query revocation status
- revoke the capability
- mint a real receipt with `chio check`
- export an offline evidence package
- verify that package with `chio evidence verify`

## What It Demonstrates

- capability issuance through the shared trust-control HTTP API
- capability status and revocation through the Chio CLI
- receipt creation without any HTTP app or framework
- offline receipt verification through exported evidence

## Files

```text
ARCHITECTURE.md
README.md
policy.yaml
run-trust.sh
smoke.sh
test_verify_artifacts.py
verify_artifacts.py
```

## Run

Start the trust-control service only:

```bash
./run-trust.sh
```

Run the full trust + receipt verification smoke flow:

```bash
./smoke.sh
```

Run the artifact verifier tests:

```bash
python3 -m unittest discover -s . -p 'test_*.py'
```
