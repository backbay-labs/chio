# Paper Evidence Ledger

This file maps the paper's results to the implementation, tests, proofs, and
measurements that support them. It is a review aid, not part of the protocol.

## Supported results

| Result | Evidence | Scope |
| --- | --- | --- |
| Receiver-owned treaty checks run before a cross-organization tool call. | `ChioRuntimeAdmissionHook::evaluate`; runtime admission tests; dispatch-capable denial benchmark | Trusted runtime classification, kernel, and stores |
| Request metadata cannot install the receiver's trust roots or dynamic trust bundle. | `treaty_ref_from_request`; request-smuggling tests | Provisioning outside the request path is an operational control |
| Two distinct configured keys sign the same canonical treaty-bound predicate. | `verify_chio_bilateral_dsse_envelope`; strict bilateral verifier tests | Proves key control, not independent organizational control |
| Accepted treaty material remains bound to the request and signed receipt. | `VerifiedFederationTreatyMaterial`; kernel federation and receipt tests | Applies to the tested construction and receipt paths |
| A treaty continuation is consumed once and replay denies. | Runtime admission tests for accepted, stale, replayed, and released continuations | Durability depends on the configured store |
| The Lean finite-domain checker implements the stated implication for every receipt in its supplied domain. | `finite_refinement_sound`; `finite_refinement_exact` in `ReceiptPredicate.lean` | The caller is responsible for choosing a complete domain; Rust complexity limits are outside the theorem |
| The independent Rust interpreter agrees with the runtime bounded evaluator on the test corpus. | `treaty_predicate_diff.rs`; every atom; 1,024 cases for each compound property | Inputs are within the runtime limits; this is differential testing, not extraction or a Rust refinement proof |
| All 20 named negative cases return the expected denial. | `treaty-runtime-negative-corpus.json`; matrix runner | Named attacks only |
| The complete pre-dispatch treaty-denial path leaves the tool uninvoked. | Criterion benchmark with a dispatch counter and signed SQLite denial receipt | Single-host release-profile configuration |
| The local three-vendor workflow produces and verifies a complete buyer package. | Runtime harness, buyer CLI, package verifier | Deterministic loopback, not separately administered deployment |

## Measurements

The retained result files report:

- pre-dispatch treaty denial: 11.124 ms p50 and 20.530 ms p99;
- complete local buyer workflow: 2.488 s p50 and 3.291 s p99;
- 20 complete-workflow samples and 30 component samples;
- a 51,843-byte buyer package.

The 2.488 s result includes three-vendor process orchestration, SQLite,
package generation, buyer CLI startup, schema validation, and semantic review.
It is not receiver-hook latency.

## Not established

- Two configured keys do not prove two independent organizations.
- The Lean development does not verify the Rust runtime.
- A finite test domain does not cover receipts omitted from that domain.
- The single-host experiment does not estimate wide-area or concurrent
  deployment behavior.
- The buyer package does not prove remote process integrity or legal effect.
