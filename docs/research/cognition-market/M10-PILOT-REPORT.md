# M10 Single-Operator Pilot Report

## Verdict

The M10 product exit passed on candidate
`e77b19ac1c0c7120d19963bff9f27c91a93c6f45`. The pilot used the installed
`chio` binary, one deployable local operator, and distinct scoped seller and
buyer credentials. It did not give either agent the global service token.

This is a local single-operator result. It is not evidence for cross-operator
fair exchange, stochastic research markets, auctions, or public hosted demand.

## Workload and outcomes

The seller admitted ten distinct verified fixes over ten failing-to-passing Git
revision pairs. The corpus covered bounds, stable ordering, remainder handling,
boolean parsing, median calculation, retry caps, zero denominators,
case-insensitive headers, secret redaction, and retry classification.

- Findings admitted: 10
- Purchases captured: 5
- Durable purchase jobs: 5
- Durable terminals: 5
- Duplicate captures: 0
- Pilot failures: 0
- Client coverage: four Python purchases and one TypeScript purchase
- Admission time: 1,801 ms minimum, 2,003.5 ms median, 2,032 ms maximum
- Recorded normal purchase time: 2,585 ms minimum, 2,923.5 ms median,
  2,948 ms maximum

Every buyer retrieved a public proof, passed it through the Rust reference
verifier, purchased the Finding, decoded the verified-fix payload, and wrote the
patch without applying it to a source workspace.

## Restart and replay

The qualifier observed a durable purchase job before its terminal, stopped the
operator process at that active boundary, killed it, and restarted from the
same profile and databases. Retrying the exact buyer request recovered one
captured terminal. A second exact replay returned the same result and terminal
digest set. The measured delta was one job, one terminal, and one capture.

After all five purchases, another exact replay left both the five terminal
digests and the capture count unchanged.

## Challenge, retraction, and tamper controls

The buyer filed one controlled evidence-invalid challenge against a purchased
Finding. The scoped seller then issued a voluntary retraction. An immediate
status read returned an inclusion proof for the retracted Finding, including
across the status-clock edge that previously caused a one-second rollback
failure.

The qualifier also altered signed Finding material in a retrieved proof bundle.
Both the Rust reference verifier and the TypeScript SDK boundary rejected it.
Python separately exercises altered-proof rejection in its SDK test suite.

## Reproduction

Run from a built candidate:

```bash
cargo build -p chio-cli
./scripts/qualify-cognition-market-pilot.py
```

The full per-run report is written to
`target/cognition-market-pilot/report.json`. The committed privacy-safe
aggregate is [M10-PILOT-REPORT.json](./M10-PILOT-REPORT.json).
