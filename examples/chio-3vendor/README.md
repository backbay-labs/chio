# chio-3vendor

Demonstrates the three-vendor buyer/auditor proof-package and bilateral cosign
flow using the `chio-attest-loopback` fixture library.

The example generates a deterministic set of attestation fixtures for a
three-vendor scenario: a buyer, two providers, and an auditor. It exercises:

- `fresh_proof_package` and `verify_package` from `chio-attest-loopback`
- A selective-disclosure proof over the buyer-auditor package
- A verifier trust bundle and verification context
- Pheromone relay fixtures (deposit, gossip batch, transit policy, peer
  weights, concentration, and catchup frames)
- A runtime-spine bundle covering runtime policy, trust, evidence, and
  proof-regeneration inputs
- Signed negative-case inputs for boundary testing

## Run

From the repository root:

```bash
# Print the buyer-auditor proof package JSON to stdout:
cargo run --bin generate-chio-proof-package --quiet

# Write all fixtures to a directory:
cargo run --bin generate-chio-proof-package --quiet -- --out-dir /tmp/chio-3vendor-out

# Print the verifier report instead:
cargo run --bin generate-chio-proof-package --quiet -- --report
```

## Regenerate committed fixtures

The committed fixtures under `fixtures/` are produced by
`generate-chio-three-vendor-fixtures`:

```bash
cargo run --bin generate-chio-three-vendor-fixtures --quiet
```

Running this command re-writes every JSON file under `fixtures/` using the
same deterministic seed as the checked-in corpus. Run it after changing the
loopback library or the fixture schemas to keep the committed files in sync.

## Fixture layout

```text
fixtures/
  buyer-auditor-proof-package.json   - proof package for the buyer/auditor pair
  selective-disclosure-proof.json    - selective-disclosure proof over the package
  verifier-trust-bundle.json         - verifier trust bundle document
  verification-context.json          - verification context
  verifier-report.json               - output of verify_package
  negative-cases.json                - signed negative-case boundary inputs
  treaty-runtime-negative-corpus.json - treaty runtime negative corpus
  pheromone/                         - pheromone relay fixtures
    deposit.json                     - signed pheromone deposit
    gossip-batch.json                - gossip batch frame
    transit-policy.json              - transit policy
    peer-weights.json                - peer weight document
    concentration.json               - concentration frame
    query-report.json / receive-report.json / health-report.json
    relay/                           - per-hop relay frames
    alert-assurance/                 - alert assurance frames
  runtime-spine/                     - runtime policy and evidence bundle
    bundle.json                      - full runtime bundle
    runtime-policy-body.json         - runtime policy body
    runtime-trust-body.json          - runtime trust body
    runtime-peer-weights-body.json   - peer weight body
    runtime-step-evidence.json       - step evidence
    scenario.json / request.json     - scenario and request inputs
    runtime-proof-*.json             - proof regeneration inputs and reports
```

## See also

- `crates/chio-attest-loopback/` - the fixture library this example wraps
- `crates/chio-attest-buyer-core/` - buyer-side attestation types
- `crates/chio-pheromone/` - pheromone deposit and observation cost types
- `docs/integrations/` - integration guides for the broader attestation flow
