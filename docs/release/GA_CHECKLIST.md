# GA Checklist

> **PRE-RELEASE:** This repository has not shipped a public GA release. Treat
> checked items below as **local-only** evidence unless a row explicitly says
> hosted CI was observed on the candidate commit. Do not cite this checklist as
> external proof of production readiness.

Use this checklist before claiming general-availability readiness for the
current v1-only pre-release Chio candidate.

This checklist is procedural. Use
[RELEASE_AUDIT.md](RELEASE_AUDIT.md) for the authoritative repo-local
release-go decision,
[RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md) for supported scope, and
[QUALIFICATION.md](QUALIFICATION.md) for the required evidence lanes.

- [x] `./scripts/ci-workspace.sh` passes *(local only)*
- [x] `./scripts/check-sdk-parity.sh` passes *(local only)*
- [x] `./scripts/check-web3-contract-parity.sh` passes *(local only)*
- [x] `./scripts/qualify-release.sh` passes *(local only)*
- [x] local web3 qualification, `e2e`, ops-control, and promotion lanes pass *(local only)*
- [x] release-input guards prevent generated artifacts from entering source *(local only)*
- [x] dashboard release build and test lane is green *(local only)*
- [x] TypeScript SDK pack/install qualification is green *(local only)*
- [x] Python wheel and sdist qualification is green *(local only)*
- [x] Go module release qualification is green *(local only)*
- [x] trust-control deployment, backup/restore, upgrade, and rollback are documented
- [x] hosted edge admin and health diagnostics are documented
- [x] formal/spec launch evidence boundary is explicit in protocol and release docs
- [x] partner-proof materials are updated to the current Chio surface
- [x] `spec/PROTOCOL.md` reflects the current pre-release repository profile
- [x] standards-submission drafts exist for receipts and portable trust
- [x] README and SDK docs align to the current pre-release contract
- [x] release audit and risk register are updated for this candidate
- [ ] hosted `CI` workflow green on the candidate commit *(hosted CI pending)*
- [ ] hosted `Release Qualification` workflow green on the candidate commit *(hosted CI pending)*
- [ ] hosted web3 bundle under `target/release-qualification/web3-runtime/`
  includes runtime, `e2e`, ops, and promotion evidence for the candidate *(hosted CI pending)*
- [ ] final release tag and publication decision taken by operator
