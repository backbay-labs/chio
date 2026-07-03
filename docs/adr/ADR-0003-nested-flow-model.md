# ADR-0003: Nested Flow Model

- Status: Proposed
- Decision owner: protocol and runtime lanes

## Context

Sampling and elicitation introduce nested workflows:

- a server handling one request can ask the client for a model generation
- a server handling one request can ask the client for structured user input

Chio needs a model that preserves:

- traceability
- user control
- client credential control
- receipt lineage

The two broad options are:

1. child requests inside the same session
2. nested sub-sessions

## Decision

Chio will model sampling and elicitation as child requests within the same session.

Each child request will have:

- its own request ID
- a parent request ID
- its own receipt
- explicit approval state where applicable

Final parent outcomes should include lineage to child requests.

## Rationale

Using child requests in the same session:

- keeps lifecycle and auth context unified
- avoids recursively spawning transport/session abstractions
- aligns better with audit needs and cancellation behavior

Nested sub-sessions would increase complexity in exchange for little practical benefit in the current architecture.

## Consequences

### Positive

- simpler state machine
- easier receipt correlation
- easier cancellation and progress handling

### Negative

- the session layer must handle parent-child request lineage explicitly
- nested request policies must be designed carefully to avoid privilege confusion

## Required follow-up

- define parent-child request schema in core types
- define receipt lineage fields
- define nested-flow policy defaults
- define cancellation behavior for parent and child requests

## Guardrail

Sampling and elicitation must default to deny unless:

- the session negotiated support
- policy allows the nested flow
- the capability or operation model permits it
