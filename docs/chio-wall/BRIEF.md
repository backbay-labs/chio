# Chio-Wall Brief

Chio-Wall is a companion app on Chio. It records tool-boundary control evidence
for information-domain separation workflows, reusing Chio's signing, checkpoint,
publication, and verification substrate.

See [`README.md`](README.md) for the full documentation suite.

## Problem

AI agents complicate traditional information-barrier controls: context and
tooling span systems quickly, automated workflows are harder to observe than
human communication alone, and existing barrier tooling is not built around
agent-to-tool invocation traces. Chio-Wall addresses the tool-boundary evidence
problem specifically; it does not claim to solve every model-memory or
prompt-injection risk on its own.

## What it does

Using Chio capability and guard mechanics, Chio-Wall:

- scopes tool access by information domain
- denies cross-domain tool access where policy requires it
- records signed allow or deny evidence
- publishes those records into the same checkpoint and verification framework

Core evidence objects: a domain-scoped authorization context, the guard outcome,
the denied-access record, and the retained policy and configuration references.

## Proof boundary

Chio-Wall can support proof that the configured tool-boundary rule was
evaluated, proof that an action was allowed or denied under a specific policy
reference, and durable records for barrier review and investigation.

It does not prove absence of model memorization, absence of prompt-injection
risk, completeness of broader barrier operations, or overall MNPI compliance by
itself.
