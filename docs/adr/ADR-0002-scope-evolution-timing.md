# ADR-0002: Scope Evolution Timing

- Status: Proposed
- Decision owner: protocol and policy lanes

## Context

Current `ChioScope` is tool-centric:

- `ChioScope { grants: Vec<ToolGrant> }`

That is workable for the prototype, but resources, prompts, sampling, and elicitation will not fit cleanly forever as tool-like shapes.

There are two timing options:

1. Generalize the grant model immediately.
2. Keep tool-only grants through early tool parity and generalize before non-tool features land.

## Decision

Chio will keep `ToolGrant` as the operational grant type through early MCP tool parity work.

Before resources and prompts become first-class runtime features, Chio will introduce a broader grant model, likely an enum-based `Grant` family.

## Rationale

Immediate generalization would increase churn before the MCP tool edge even exists.

Delaying all scope evolution until after resources and prompts land would create awkward APIs and probably force fake tool semantics into non-tool features.

The staged approach keeps early progress moving while forcing generalization before the architecture becomes distorted.

## Consequences

### Positive

- tool-parity work can start sooner
- scope evolution remains a deliberate pre-resource step rather than a late rewrite
- semver-significant changes happen before `v1`, not after

### Negative

- there will be one planned data-model transition
- some early APIs may need careful naming so they do not imply tool-only forever

## Required follow-up

- design `ResourceGrant`, `PromptGrant`, `SamplingGrant`, and `ElicitationGrant`
- identify every kernel and policy assumption that currently implies tool-only scope
- schedule the `Grant` transition before resource and prompt implementation starts

## Trigger to revisit

If non-tool features need to start before MCP tool parity is stable, revisit immediately and broaden the scope model earlier.
