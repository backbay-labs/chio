# Risk Register

This register tracks the known non-blocking risks that remain after the local
v1-only pre-release production-candidate closeout.

| Risk | Current posture | Mitigation |
| --- | --- | --- |
| Hosted workflow results are not observable from every local environment | local launch evidence is complete, but external publication stays on hold until hosted CI is green | require hosted `CI` and `Release Qualification` success before tagging |
| Cluster replication remains deterministic leader/follower rather than consensus-based | acceptable for supported deployment scope, not for stronger distributed-trust claims | keep consensus work out of release claims and future milestone separately |
| Enterprise federation does not yet provide automatic SCIM lifecycle management | acceptable for current provider-admin and observability scope | keep provider-admin records explicit and fail closed when incomplete |
| Portable trust does not synthesize cross-issuer reputation | intentional design choice, not a regression | document per-credential evaluation semantics and avoid broader claims |
| A2A still lacks custom auth beyond the shipped matrix | known boundary for partner integrations | keep unsupported schemes explicit and fail closed during discovery/invocation |
| Formal verification depends on audited external assumptions and strict Rust-linkage gates | controlled by the implementation-linked proof manifest, P1-P10 theorem inventory, assumption registry, Aeneas production extraction plus equivalence, public Kani harnesses, no-bypass checks, executable tests, and qualification artifacts | keep protocol, partner, website, and release claims tied to `formal/proof-manifest.toml`, `formal/assumptions.toml`, `formal/theorem-inventory.json`, `target/formal/proof-report.json`, `docs/reference/CLAIM_REGISTRY.md`, and strict verification gates |

## Formal Verification Claim Rules

This risk is considered controlled for the current release only under these
rules:

- do not describe Chio as formally verified without also naming the published
  audited assumptions and implementation-linked boundary
- do not say P1-P10 prove concrete crypto libraries, OS clocks, TLS, SQLite,
  subprocess isolation, hosted registries, external chains, clustering, or
  settlement from first principles
- do not say Creusot/Kani production refinement is complete unless the strict
  Rust verification lane has actually passed in CI
- do say Chio's security-critical protocol semantics are formally verified and
  implementation-linked, subject to `formal/proof-manifest.toml`,
  `formal/assumptions.toml`, and `formal/theorem-inventory.json`
- do require the proof report to include gate status, tool versions, theorem
  source locations, tracked artifact hashes, and generated Aeneas artifact
  hashes before using release-facing formal claims
- do say runtime and partner-facing claims outside that boundary are backed by
  Rust tests, conformance tests, smoke tests, and release qualification
