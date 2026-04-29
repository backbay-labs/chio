# trajectory-2

Post-trajectory-1 planning artifacts for the next ten code-focused Chio
milestones. trajectory-1 (`.planning/trajectory/`) executed M01-M10
autonomously on `project/roadmap-04-25-2026`; trajectory-2 builds on what
that closed and attacks the gaps it left.

## Genesis

trajectory-2 was produced by a two-round seven-agent debate (2026-04-29).
Round 1 was insufficiently grounded in the live state and largely
re-described trajectory-1 work. Round 2 corrected that: agents were briefed
with what each trajectory-1 milestone shipped (M01 spec codegen + canonical
JSON vectors, M02 fuzzing baseline, M03 capability algebra properties,
M04 deterministic replay, M05 async kernel, M06 WASM guard platform with
OCI + cosign, M07 provider conformance, M08 browser/edge SDK, M09
attestation surface, M10 TEE replay) and asked to refine.

The seven lenses: protocol purist, SDK / integration evangelist, quality
hawk, performance / scale engineer, security / cryptography researcher,
developer experience advocate, wildcard visionary. The final ten capture
multi-lens convergence first, single-lens but high-evidence second, and
two long-bet items third.

trajectory-2 scope: pure engineering output. Releases, design partner work,
certifications, and other external workstreams remain explicitly excluded.

## The Ten Milestones

| # | Title | One-liner |
|---|-------|-----------|
| 01 | [Workspace Error Taxonomy + Doctor + LSP](01-error-taxonomy-doctor-lsp.md) | Stable `urn:chio:error:*` registry, `chio doctor`, and `chio-lsp` ending the 2,326-line `dispatch.rs` one-shot-string regime. |
| 02 | [Mutation Gate + Cross-SDK Verdict Differential](02-mutation-and-cross-sdk-differential.md) | `cargo-mutants` 80%-kill gate on trust-boundary crates plus a cross-SDK semantic verdict harness that diffs Rust/Python/TS/WASM verdicts on a shared scenario corpus. |
| 03 | [PQ-Hybrid Signing + TEE Quote Verifier](03-pq-hybrid-and-tee-quote-verifier.md) | ML-DSA-65 hybrid signatures and Intel TDX / AMD SEV-SNP / AWS Nitro NSM quote verification consolidated in `chio-attest-verify`. |
| 04 | [Recursive Delegation + Revocation Oracle](04-recursive-delegation-revocation-oracle.md) | Sub-second sparse-Merkle revocation propagation plus Lean 4 proofs for multi-tier delegation; re-attacks the v3.18 bounded-claim retreat. |
| 05 | [Adversarial Receipts + Guard Escape + Threat-Model-as-Code](05-adversarial-escape-threat-model.md) | `chio-adversarial-suite`, WASM guard escape fuzz harness, and a CI-load-bearing threat-model registry that fails build on uncovered threat IDs. |
| 06 | [Performance Hardening Pack](06-performance-hardening-pack.md) | Bounded backpressure on `chio-otel-receipt-exporter` and signing mpsc, SQLite group-commit, `wasmtime::InstancePre` guard pool, `CanonicalBytes` zero-copy newtype. |
| 07 | [Adoption Beachhead Pack](07-adoption-beachhead-pack.md) | `@chio/ai-sdk-middleware` and `@chio/next` for Vercel AI SDK, `arc mcp wrap` for Cursor / Claude Desktop / Continue / Zed, and Gemini / Mistral / Groq / Ollama provider adapter pack. |
| 08 | [chio-arena: Adversarial Replay Coliseum](08-chio-arena-replay-coliseum.md) | Deterministic multi-agent simulator on top of M04 replay and M05 async kernel; co-evolving adversaries auto-promote into the M01 vector corpus. |
| 09 | [Economic Layer + Lineage](09-economic-layer-and-lineage.md) | Wake `chio-credit`, `chio-settle`, `chio-reputation`, and `chio-mercury` as a guard marketplace with priced installs settled at receipt finalization, plus `chio-lineage` provenance graph. |
| 10 | [Hardware Custody + Policy-Bound Model Cards](10-hardware-custody-and-model-cards.md) | WebAuthn-as-authn (passkey assertion mints audience-bound capability) and `chio-weights` signed model cards binding `(weights_hash, allowed_capabilities, banned_tools)`. |

## Dependency graph

```
                     trajectory-1 closes
                            |
                            v
          +-----+-----+-----+-----+-----+
          |     |     |           |     |
          v     v     v           v     v
         M01   M02   M06         (M07) (M08)
       error  mut+   perf        adoption arena
       /lsp   diff   pack
          \   /  \    \           |     |
           v v    v    v           |     |
            M03   M04   M05        |     |
            PQ+   delg+ adversaria.|     |
            tee   revoc threat     |     |
              \      \   /         |     |
               \      v v          |     |
                \    M09 econ+lineage    |
                 \      |                |
                  \     v                v
                   \   M10  hardware custody +
                    \--+    policy-bound model cards
```

Detail:

- **M01** unblocks M02, M07, and M09 (LSP + error codes are how every other
  surface reports failures in trajectory-2).
- **M02** unblocks M05 (mutation kill score is the calibration for the
  adversarial / escape suite's incremental value) and M07 (cross-SDK
  differential prerequisites the new framework adapters).
- **M03** unblocks M04 (PQ signing on revocation-oracle roots) and M10
  (hardware custody envelopes use the verifier surface).
- **M04** unblocks M09 (delegation primitives are how guard purchases
  attribute revenue across kernels) and M10 (model-card binding is a
  delegation-shape).
- **M05** is the regression net for everything below it.
- **M06** lands early because every later milestone benefits from bounded
  backpressure and reduced per-receipt allocations; M09 lineage especially.
- **M07** depends only on trajectory-1 substrate; ships in parallel with
  Wave 2.
- **M08** depends on M04 (replay), M05 (async kernel), M07 (verdict oracle).
- **M09** depends on M04 (delegation), M06 (perf), M07 (provider matrix
  defines guard surface).
- **M10** depends on M03 (verifier surface), M04 (delegation envelope),
  M07 (model-binding scope set).

## Recommended Execution Waves

### Wave 1: foundation (parallel)
- **M01** Error taxonomy, doctor, LSP
- **M02** Mutation gate + cross-SDK verdict differential
- **M06** Performance hardening pack

### Wave 2: trust-boundary regression nets
- **M03** PQ-hybrid signing + TEE quote verifier
- **M04** Recursive delegation + revocation oracle
- **M05** Adversarial + escape + threat-model-as-code

### Wave 3: breadth and ambition
- **M07** Adoption beachhead pack
- **M08** chio-arena replay coliseum

### Wave 4: capstones
- **M09** Economic layer + lineage
- **M10** Hardware custody + policy-bound model cards

## Cross-doc invariants

| Artifact | Owner | Consumers | Notes |
|----------|-------|-----------|-------|
| `urn:chio:error:*` registry (`spec/errors/registry.yaml`) | M01 | M07 (provider error doctests consume it), M02 (verdict-diff classifies by code), all CLI surfaces | Every `Err(_)` in `dispatch.rs` carries a code; SDKs codegen typed enums from the registry. |
| `chio-lsp` schema bindings | M01 | M07 (Vercel/Next adapter editor support), all `chio.yaml` consumers | Server lives at `crates/chio-lsp/`; VSCode and Zed extensions ship in `editors/`. |
| Cross-SDK verdict-matrix harness | M02 | M07 (each new adapter must pass), M05 (adversarial suite uses it as oracle), M08 (arena uses it as referee) | Lives in `crates/chio-conformance/verdict_matrix/`; corpus is hash-pinned. |
| `chio-attest-verify` PQ + TEE-quote surface | M03 | M04 (revocation roots can be PQ-signed), M09 (lineage anchor proofs), M10 (custody envelopes) | Single verifier crate; M03 must NOT fork. |
| `chio-revocation-oracle` sparse-Merkle CRL-Lite | M04 | M09 (revoking guard publishers cascades through marketplace), M10 (passkey-credential revocation kills issued capabilities) | New crate; epoch-stamped roots signed via the M03 surface. |
| `chio-adversarial-suite` corpus | M05 | M02 (mutants test against suite cases), M08 (arena outputs auto-promote into suite) | Crate `crates/chio-adversarial-suite/`; one JSON file per attack class. |
| `CanonicalBytes` newtype | M06 | M03 (PQ signing canonicalization input), M09 (lineage anchor encoding) | Lives in `chio-core-types`; existing receipt path migrates with byte-equivalence proofs against trajectory-1 M01 vectors. |
| Threat-model registry (`spec/security/chio-threat-model.v1.json`) | M05 | M03 (adds `pq_signature_downgrade` + `tee_quote_forgery`), M04 (consumes existing `delegation_chain_abuse` + revocation rows), M10 (adds `passkey_credential_theft` + `audience_confusion` + `weights_hash_spoof`) | M05 owns the load-bearing CI coverage gate; producers append rows in their P0 wave-openers. |

## House rules

Inherited from `/CLAUDE.md`:

- No em dashes (U+2014). Use hyphens or parentheses.
- Fail-closed: errors deny access. Invalid policies reject at load time.
- Conventional commits.
- Clippy `unwrap_used = "deny"` and `expect_used = "deny"` workspace-wide.

trajectory-2 specific:

- Trajectory-2 ticket IDs reference each other only via `depends_on`.
  Cross-trajectory references go in `soft_deps` as string sentences.
- Each milestone has exactly one narrative file at the trajectory-2 root.
- Per-phase ticket files live under `tickets/M{NN}/P{n}.yml`.
- `tickets/manifest.yml` is generated; do not hand-edit.
- Authoring contract: `STYLE.md`.

## Open questions resolved (2026-04-29)

The seven-agent debate produced four decisions that were already locked
before authoring began:

1. **Bundle vs unbundle.** Bundled. Several milestones collapse 2-4 round-2
   proposals into one shippable surface. This is the inverse of trajectory-1's
   single-lens-per-milestone discipline; trajectory-2 prefers shipping
   coherent surfaces over slicing them across waves.
2. **Item ordering.** chio-arena (M08) ships before economic layer (M09) so
   that arena-generated adversarial corpora are available to the
   reputation-weighted guard marketplace.
3. **Item 10 ambition.** Both halves (hardware custody + model cards) are in
   scope. If schedule pressure surfaces, custody is the half that ships.
4. **Heretical reservations.** Wildcard V02 (chio-zk-verify) and V07
   (chio-mesh consensus) are explicitly out of scope for trajectory-2 and
   penciled for the post-trajectory-2 review.

## File map

```
.planning/trajectory-2/
  README.md                 (this file)
  STYLE.md                  (authoring contract)
  EXECUTION-STATE.json      (seed state, milestone status table)
  EXECUTION-BOARD.md        (waves, freezes, ownership detail)
  OWNERS.toml               (path -> reviewer mapping)
  freezes.yml               (freeze windows during trust-boundary phases)
  decisions.yml             (locked design decisions per milestone)
  01-error-taxonomy-doctor-lsp.md
  02-mutation-and-cross-sdk-differential.md
  03-pq-hybrid-and-tee-quote-verifier.md
  04-recursive-delegation-revocation-oracle.md
  05-adversarial-escape-threat-model.md
  06-performance-hardening-pack.md
  07-adoption-beachhead-pack.md
  08-chio-arena-replay-coliseum.md
  09-economic-layer-and-lineage.md
  10-hardware-custody-and-model-cards.md
  tickets/
    schema.json             (extended agent_role enum)
    manifest.yml            (generated; concatenation of per-phase files)
    M01/P0.yml ... P{N}.yml
    M02/...
    ...
    M10/...
```
