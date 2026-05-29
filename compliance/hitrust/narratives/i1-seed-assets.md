# Asset Management Narrative

Asset-management evidence exists in the repository: cargo-vet audits
(`supply-chain/audits.toml`), the dependency lock
(`supply-chain/imports.lock`), and the SBOM and CVE-monitoring workflows
(`.github/workflows/sbom.yml`, `.github/workflows/cve-monitor.yml`).

This family is self-assessed as implemented. Remaining work is row-level
control mapping, not new asset evidence.

Fail-closed note: an asset row without SBOM or owner evidence remains a
gap.
