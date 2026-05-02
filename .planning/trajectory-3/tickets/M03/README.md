# M03: Hosted CI Truth + Reproducible Builds

**Wave:** W1  |  **Trust-boundary:** yes  |  **Tickets:** TBD  |  **Effort weeks:** 4/6/9

## In one paragraph

M03 replaces the admin-merge bypass with real hosted CI on GitHub
Actions hosted runners (ubuntu-24.04 + macos-14) and ships
reproducible-build artifacts with checksum publication. Release gate
is RELEASE_AUDIT: hosted CI green for the v3.18 release commit, and a
reproducible-build hash externally reproduced by an independent
third party. Implementation: hosted CI workflows, SLSA-style
provenance, public checksum index.

## Phases at a glance (placeholder; IMPLEMENT phase fills in)

| Phase | One-liner |
|-------|-----------|
| P0 | Audit doc + billing restored + bypass-mode bisect plan |
| P1 | Hosted CI workflows re-enabled; failures from bypass surfaced |
| P2 | Reproducible-build pipeline scaffold |
| P3 | SLSA-style provenance + checksum publication |
| P4 | External third-party rebuild + hash match recorded |
| P5 | v3.18 release commit retroactively certified under new CI |

## Locked decisions

- D13 hosted runner choice (ubuntu-24.04 + macos-14); third-party
  reproducer is independent

## Active freezes

none directly; M03 owns the hosted-CI workflow files.

## When this milestone is done

- Hosted CI green for v3.18 release commit.
- Reproducible-build hash published and externally reproduced.
- Audit doc records third-party rebuilder identity + matched hash.
