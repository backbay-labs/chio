# GitHub Actions workflows

## The `chio-pheromone-*` gate family is intentionally kept as separate files

There are 15 `chio-pheromone-*.yml` workflows. They look like near-duplicates but
are deliberately NOT consolidated into a single matrix workflow. This note
records why.

### The 15 files

Relay subsystem gates (each runs one `scripts/check-<name>.sh`):

- `chio-pheromone-relay.yml`
- `chio-pheromone-relay-ops.yml`
- `chio-pheromone-relay-observability.yml`
- `chio-pheromone-relay-alert-routing.yml`
- `chio-pheromone-relay-alert-delivery.yml`
- `chio-pheromone-relay-alert-handoff.yml`
- `chio-pheromone-relay-alert-assurance.yml`
- `chio-pheromone-relay-alert-assurance-archive.yml`
- `chio-pheromone-relay-alert-assurance-archive-package.yml`
- `chio-pheromone-relay-alert-assurance-archive-hardening.yml`
- `chio-pheromone-relay-alert-assurance-export.yml`
- `chio-pheromone-relay-alert-assurance-external-retention.yml`
- `chio-pheromone-directory-lifecycle.yml`
- `chio-pheromone-runtime.yml`
- `chio-pheromone-transit.yml`

### Why not one matrix workflow

Each file carries its own `on.paths` trigger (a different set of crate, spec,
script, and doc globs). A single matrix workflow has one `on:` block and cannot
express per-matrix-entry path filters, so collapsing them would force every gate
to run on every pheromone-related change. That defeats the path-scoping these
files exist to provide.

### Why not the reusable-workflow (`workflow_call`) pattern either

The standard alternative is to extract the shared job body into one
`workflow_call` reusable workflow and reduce each file to a thin path-triggered
caller. This is declined because the job bodies are NOT uniform. They fall into
four distinct shapes:

| Shape | Files | `permissions:` block | `Swatinem/rust-cache` | `setup-node` | node version |
| ----- | ----- | -------------------- | --------------------- | ------------ | ------------ |
| A | relay, relay-ops, directory-lifecycle, runtime, transit | none | no | no | - |
| B | relay-observability | none | no | yes | 22 |
| C | alert-routing, alert-delivery, alert-handoff, alert-assurance | `contents: read` | yes | yes | 24 |
| D | the five `...-assurance-archive` / `-export` / `-external-retention` | `contents: read` | yes | no | - |

A reusable workflow could in principle express these differences with
`workflow_call` inputs (booleans gating the cache / node steps via `if:`, a
string for the node version, strings for the gate name and script path). It is
still declined for four reasons, any one of which is sufficient:

1. The bodies are not "near-identical": the four shapes mean the reusable
   workflow would need conditional (`if: inputs.*`) steps. That is a
   behavior-bearing rewrite, not a mechanical de-duplication, and the resulting
   single file is harder to reason about than the 15 flat files it replaces.
2. Permissions posture differs. Shapes A and B set no `permissions:` block (they
   inherit the repository / org default token scope); shapes C and D pin
   `contents: read`. Under `workflow_call`, the effective token scope is governed
   by the called workflow plus the caller job's `permissions:`. Folding files
   with different permission postures into one reusable workflow risks silently
   changing the token scope for some gates, over-granting a fail-closed CI
   surface.
3. The node-version split (22 in shape B vs 24 in shape C) cannot be resolved
   from the YAML alone. It may be an intentional pin or stale drift.
4. Required status-check matching. Branch-protection / ruleset config lives in
   GitHub settings outside this repo. Converting these to callers changes how
   each check surfaces (it would appear as `caller / reusable-job` instead of
   the current top-level job name), which can silently break a required-check
   rule.

### If this is revisited

Do it on a branch where GitHub Actions can run, and confirm with Actions
executing: the per-file `on.paths` triggers still gate correctly on both
`pull_request` and `push`; the effective token permissions per gate are
unchanged; the node version choice is deliberate; and the surfaced check names
still satisfy whatever required-status-check rules are configured in GitHub
settings.
