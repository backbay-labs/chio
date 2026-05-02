# HITRUST Walkthrough Week 11: Asset Management and Supply Chain

**Milestone:** M09.P1.T5
**Scope:** Chio v3.18 healthcare design-partner deployment
**Families:** Asset Management, Systems Acquisition Development and Maintenance
**Status:** complete, no halt candidate

## Evidence reviewed

| Evidence | Purpose |
|----------|---------|
| `supply-chain/**` | SBOM, inventory, cargo-vet, supply-chain records |
| `supply-chain/audits.toml` | third-party dependency audit ledger |
| `.github/workflows/cve-monitor.yml` | CVE monitoring pipeline |
| `.planning/trajectory-3/audits/M06-supply-chain.md` | milestone evidence rollup |
| `.planning/trajectory-3/audits/M03-ci-restoration.md` | reproducible build and provenance context |

## Assessor observations

- The SBOM and cargo-vet ledger are acceptable evidence families for
  asset and supplier rows once the P3 bundle pins the exact v3.18
  artifact hashes.
- The assessor requested a concise bridge explaining TLA+ and Apalache
  outputs in non-formal-method terms.
- CVE-monitoring workflow presence is useful, but P3 must provide the
  run result or exported monitoring receipt for the assessed version.
- Out-of-tree cloud asset inventory remains a gap until the deployment
  owner attaches the design-partner environment inventory.

## Questions captured

| Question | Owner | Disposition |
|----------|-------|-------------|
| What artifact hash identifies the assessed v3.18 build? | M03/M09 | P3 bundle index |
| Which package list is in the production deployment? | M06/M09 | P3 SBOM attachment |
| How do formal invariants support acquisition and development controls? | M09 | P2 formal evidence bridge |

## Gap preview

Repository supply-chain evidence is partially ready. Production cloud
asset inventory and final v3.18 evidence hashes are P2/P3 items.
