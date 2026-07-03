# Chio Identity and Artifact Transition

**Status:** Active contract

## Purpose

This document defines the Chio namespace contract across portable-trust
identity and signed artifact families. The rename is a clean cutover: maintained
runtime surfaces issue and accept Chio identifiers only.

## Identity Decision

### `did:chio`

`did:chio` is the shipped canonical DID method for Chio.

That means:

- existing `did:chio` identifiers are canonical
- resolvers and verifiers accept `did:chio` only on maintained Chio surfaces
- passports, verifier policies, certifications, and evidence packages must use
  `did:chio` before import into the current runtime
- no historical Rust aliases remain; `DidChio` is the sole Rust type

## Artifact Schema Decision

The maintained schema surface is `chio.*`.

Current Chio behavior:

- new Chio-branded artifacts issue `chio.*` identifiers for the shipped
  checkpoint, DPoP, passport, verifier-policy, challenge/response,
  certification, and evidence-export families
- validators/importers reject non-Chio namespace identifiers on maintained
  runtime paths
- conversion tooling is the supported path for historical data that must be
  reintroduced into the current runtime

## Surface Policy by Category

| Category | Chio policy |
|----------|-------------|
| DID methods | `did:chio` and `DidChio` are canonical |
| Native service API | `NativeChioServiceBuilder` / `NativeChioService` are canonical |
| MCP streaming extension | `chioToolStreaming` / `chioToolStream` are canonical |
| Receipt and checkpoint schemas | new issuance uses `chio.*` |
| Passport and verifier-policy schemas | new issuance uses `chio.*` |
| Certification and evidence-export schemas | new issuance uses `chio.*` |

## Non-Goals

- automatically rewriting historical signed objects during runtime import
- requiring a one-shot migration of all stored artifacts
- preserving historical branding on maintained public APIs after the rename
