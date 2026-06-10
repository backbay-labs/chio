# GitHub Actions workflows

## The `chio-pheromone-*` gate family is kept as separate files

The 15 `chio-pheromone-*.yml` workflows look like near-duplicates but must not be
consolidated into a single matrix workflow. Two constraints rule out the obvious
collapses.

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

### A single matrix workflow cannot path-scope per gate

Each file carries its own `on.paths` trigger (a different set of crate, spec,
script, and doc globs). A single matrix workflow has one `on:` block and cannot
express per-matrix-entry path filters, so collapsing them forces every gate to
run on every pheromone-related change, defeating the path-scoping these files
provide.

### The reusable-workflow (`workflow_call`) pattern does not fit either

Extracting the shared job body into one `workflow_call` reusable workflow with
thin path-triggered callers fails because the job bodies are not uniform. They
fall into four distinct shapes:

| Shape | Files | `permissions:` block | `Swatinem/rust-cache` | `setup-node` | node version |
| ----- | ----- | -------------------- | --------------------- | ------------ | ------------ |
| A | relay, relay-ops, directory-lifecycle, runtime, transit | none | no | no | - |
| B | relay-observability | none | no | yes | 22 |
| C | alert-routing, alert-delivery, alert-handoff, alert-assurance | `contents: read` | yes | yes | 24 |
| D | the five `...-assurance-archive` / `-export` / `-external-retention` | `contents: read` | yes | no | - |

`workflow_call` inputs could express these differences (booleans gating the
cache / node steps via `if:`, a string for the node version, strings for the
gate name and script path), but four constraints block the conversion, each on
its own sufficient:

1. The four shapes require conditional (`if: inputs.*`) steps. The resulting
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
   each check surfaces (it appears as `caller / reusable-job` instead of the
   current top-level job name), which can silently break a required-check rule.

Any consolidation must be validated on a branch where GitHub Actions runs, with
Actions executing, against four invariants: the per-file `on.paths` triggers
still gate correctly on both `pull_request` and `push`; the effective token
permissions per gate are unchanged; the node version choice is deliberate; and
the surfaced check names still satisfy the required-status-check rules
configured in GitHub settings.
