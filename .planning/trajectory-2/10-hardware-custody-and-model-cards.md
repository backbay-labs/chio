# Milestone 10: Hardware Custody + Policy-Bound Model Cards

## Lens

Identity custody and model-identity binding. One milestone, two surfaces, both
load-bearing for end-to-end provenance. The first surface is hardware-bound
custody: a server-side issuer that turns a WebAuthn / passkey assertion into a
short-lived audience-pinned capability so the browser holds zero capability
material. The second surface is `chio-weights`: signed model cards binding
`(weights_hash, allowed_capability_set, banned_tools, training_data_class)` so
the kernel will not bind a provider unless the loaded weights match a card and
the requested scopes are a subset of the card's allowed set. Both halves share
one truth: identity is something the kernel verifies, not something a runtime
asserts. If schedule pressure forces a cut, custody is the half that ships.

## Why this is on the trajectory

trajectory-1 left two specific holes that this milestone closes:

- trajectory-1 M08.P3 (browser-side signing) was filed and **rejected** in
  `docs/trust-boundary-browser-signing.md` (status `rejected`, approver
  `@bb-connor`, dated 2026-04-27). Section 2 of that document names the
  evidence that would unblock the work: "a named server-side authority that
  issues browser subkeys, a signed provisioning envelope with explicit origin,
  audience, scope, expiry, and issuer metadata, a receipt-visible delegation
  chain shaped like `root -> intermediate -> browser-subkey`, a verifier path
  that proves every browser-signed receipt traces back to a server-side root
  without trusting browser-held root material." Section 5 closes with
  "delegated signing is moved to a follow-on milestone after stronger evidence
  is written, reviewed, and approved." M10 is the follow-on milestone the
  verdict promised. The browser still does not hold a signing key; it presents
  a passkey assertion to a server-side issuer that mints a 5-minute
  audience-pinned capability. The capability is the delegated subkey the
  verdict gestured at, except it is not a key at all: it is a signed
  short-lived capability bound to the WebAuthn credential id.
- trajectory-1 M07 (`crates/chio-provider-conformance/`) shipped a
  cross-provider verdict-equality oracle so two providers can be checked for
  operational equivalence at canonical inputs. Today there is no signed
  artefact that says "this set of weights, run under this kernel policy,
  produces verdicts equivalent to that other set of weights." Operators that
  must federate model identity across an organisation have to trust filenames.
  M10's `chio-weights` model card is the signed artefact; M07's verdict
  equality is the test that two cards are operationally equivalent.

Without M10, trajectory-2's identity story stops at the kernel boundary. The
kernel knows how to verify a capability, but it does not know how to verify
that the entity presenting the capability is bound to a hardware credential
the issuer controls; and it does not know how to verify that the weights
loaded by a provider match a signed declaration of allowed scopes.

## Prior-art reckoning

trajectory-1 already shipped, and M10 preserves untouched:

- `docs/trust-boundary-browser-signing.md` (M08.P3 verdict). The verdict is
  the precondition for this milestone. M10 does not re-litigate it; it
  satisfies the named evidence requirements by building the server-side
  authority the verdict demanded.
- `crates/chio-attest-verify/` (M09 cosign bundle + Rekor surface; trajectory-2
  M03 PQ-hybrid + TEE quote backends). Both halves of M10 reuse this verifier
  rather than adding a parallel signature path. Model-card cosign bundles
  verify through `SigstoreVerifier::verify_bundle`; passkey-issued
  capabilities are signed via `HybridBackend` from trajectory-2 M03.P2.T2.
- `crates/chio-kernel-browser/` (the trajectory-1 M08 wasm-bindgen surface).
  The browser path stays verify-only at the wasm boundary. M10 adds
  `@chio/passkey` as a thin TypeScript helper sitting alongside
  `@chio-protocol/browser`; it never reaches into the wasm crate to mint or
  hold key material.
- `crates/chio-provider-conformance/` (M07). The cross-provider verdict
  equality test stays the operational-equivalence oracle for model cards;
  M10 does not fork it.
- trajectory-2 M04 revocation oracle (`crates/chio-revocation-oracle/` once
  M04.P3 lands). When a WebAuthn credential is revoked, the issuer pushes
  the revocation through the M04 oracle. Capabilities issued against the
  revoked credential are denied at the next kernel call within the M04 epoch.
  M10 does not invent its own revocation surface.
- trajectory-2 M09 lineage anchors. The public registry of model cards
  is anchored via the M09 lineage graph; M10 publishes cards into the
  registry and consumes the existing anchor proofs.

What is changed (deliberately, with discipline):

- A new crate `crates/chio-custody-hw/` houses the WebAuthn assertion
  verifier, the audience-pinned capability envelope, and the issuer service
  surface. The kernel does not learn WebAuthn; it learns to consume the
  capability the issuer mints.
- A new crate `crates/chio-weights/` houses the model-card schema, the
  cosign-bundle helper that wraps `SigstoreVerifier::verify_bundle`, and the
  `arc bind <provider> --card <path>` CLI subcommand surface.
- `crates/chio-policy/` gains `policy.weights_card_required` and
  `policy.passkey_issuer` enums that the kernel reads at boot. Invalid
  combinations reject at policy load (fail-closed).

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses. Update the date and numbers if
you re-run; do not silently let them drift.

- `crates/chio-custody-hw/`: does not exist
  (`ls crates/ | grep -c chio-custody-hw` returns `0`).
- `crates/chio-weights/`: does not exist
  (`ls crates/ | grep -c chio-weights` returns `0`).
- `crates/chio-credentials/src/`: 16 files (`artifact.rs`, `challenge.rs`,
  `cross_issuer.rs`, `discovery.rs`, `fuzz.rs`, `lib.rs`, `oid4vci.rs`,
  `oid4vp.rs`, `passport.rs`, `policy.rs`, `portable_jwt_vc.rs`,
  `portable_reputation.rs`, `portable_sd_jwt.rs`, `presentation.rs`,
  `registry.rs`, `tests.rs`, `trust_tier.rs`). The crate handles VC / SD-JWT
  / OID4VC* presentation flows. M10 does not extend it; WebAuthn is a new
  custody surface adjacent to credentials, not inside them.
  (`ls crates/chio-credentials/src/`)
- `crates/chio-attest-verify/src/lib.rs`: 131 lines, exposes
  `AttestVerifier`, `ExpectedIdentity`, `VerifiedAttestation`, `AttestError`.
  M03 grows it with `QuoteVerifier` and PQ helpers; M10 consumes the
  existing surface without forking.
- `crates/chio-policy/src/`: source layout per the trajectory-1 audit
  (counted for the policy_weights_card_required addition; pin counts on
  the day P4 opens).
- `docs/trust-boundary-browser-signing.md`: present, status `rejected`,
  decision dated 2026-04-27. The follow-on criteria in section 5 are M10's
  scope contract.
  (`grep -E '^Status:' docs/trust-boundary-browser-signing.md`)
- WebAuthn-related fixtures in the workspace (`find crates -name '*passkey*'
  -o -name '*webauthn*'`): zero today.
- Threat model rows touching custody or model-card binding
  (`grep -E '"id":\s*"(passkey_|webauthn_|model_card_|weights_hash_)'
  spec/security/chio-threat-model.v1.json`): zero today. M10 adds three
  (`passkey_credential_theft`, `audience_confusion`, `weights_hash_spoof`).

## Workspace dependency state

Reused from trajectory-1 and trajectory-2 prior milestones:

- `chio-attest-verify` (M09 + trajectory-2 M03) for cosign bundle verify and
  PQ-hybrid signing surface.
- `chio-revocation-oracle` (trajectory-2 M04) for credential revocation
  cascade.
- `chio-provider-conformance` (M07) for cross-provider verdict equality
  oracle.
- `serde`, `serde_json`, `thiserror`, `chrono` (already pinned workspace
  level).

Pinned by M10 wave-opener (P0). On the day P0 opens, re-check crates.io for
the then-current latest patch versions before pasting these. Targets at the
time of authoring (2026-04-29):

- `webauthn-rs = "0.5"` -- pure-Rust WebAuthn relying party + assertion
  verifier with FIDO Metadata Service support. Pin rationale: actively
  maintained, exposes the assertion-verify primitive without dragging an
  HTTP server framework into `chio-custody-hw`. The 0.5 line stabilises the
  passkey ergonomic surface.
- `webauthn-rs-proto = "0.5"` (companion crate with the wire types,
  matching minor with `webauthn-rs`).
- `coset = "0.3"` -- already pinned by trajectory-2 M03 for Nitro NSM
  COSE_Sign1; reused here to parse the WebAuthn attestation statement
  COSE blobs. Single workspace pin.
- `base64ct = "1"` -- pure-Rust base64 / base64url for the WebAuthn
  challenge / clientDataJSON encoding round-trip. Pin rationale:
  constant-time decoder is a security primitive.
- `proptest = { workspace = true }` -- reused for the audience-confusion
  property test in P2.

`@chio/passkey` (TypeScript) lives at
`sdks/typescript/packages/passkey/`. It depends on the existing
`@chio-protocol/browser` package for `parseCapabilityToken` and adds
**zero** new browser cryptography. The package's runtime cost is one
`navigator.credentials.get` call plus one `fetch` to the issuer.

Cargo.lock changes are confined to the P0 wave-opener. Subsequent tickets
add no new direct dependencies; they consume what P0 pins.

## Scope

In:

- New crate `crates/chio-custody-hw/` housing:
  - WebAuthn assertion verifier surface (`PasskeyVerifier`) wrapping
    `webauthn-rs` and exposing a `verify_assertion(challenge, assertion)
    -> Result<VerifiedAssertion, CustodyError>` shape. Fail-closed.
  - Audience-pinned capability envelope
    (`PasskeyCapability { audience, credential_id, scope_set, exp,
    challenge_nonce, signature }`). Five-minute fixed `exp`; clock source
    is the kernel clock not the issuer clock to keep verifier-side time
    monotonic.
  - Issuer service skeleton: an HTTP handler shape (Axum service) that
    receives a WebAuthn assertion, verifies it, calls the M03
    `HybridBackend` to sign a `PasskeyCapability`, and returns the
    capability. The service is not a binary in this milestone; it is a
    library surface mounted by `chio-control-plane` operators.
- Issuer integration with trajectory-2 M03 PQ-hybrid signing surface:
  capabilities are signed via `HybridBackend` so the audience pin
  survives PQ migration.
- Issuer integration with trajectory-2 M04 revocation oracle: revoking
  the WebAuthn credential at the issuer pushes a revocation through the
  M04 oracle. The kernel denies the next call within the M04 epoch.
- Replay-attack resistance: the issuer keeps a durable nonce store
  keyed by `(credential_id, challenge_nonce)`; a replayed
  `PasskeyCapability` rejects fail-closed.
- New crate `crates/chio-weights/` housing:
  - Signed model card schema. Required fields:
    `(weights_hash, allowed_capability_set, banned_tools,
    training_data_class, card_version, issuer, issued_at, expires_at)`.
    Canonical-JSON encoding, locked under
    `spec/schemas/model-card.v1.json`.
  - Cosign bundle helper that consumes `SigstoreVerifier::verify_bundle`
    from `chio-attest-verify`. M10 does not fork the verifier.
  - Kernel binding refusal: when `policy.weights_card_required` is set,
    the kernel refuses to bind a provider unless the provider's
    `weights_hash` matches a signed card AND the requested capability
    set is a (proper or equal) subset of the card's
    `allowed_capability_set`. Banned tools reject at provider bind, not
    at first call.
  - `arc bind <provider> --card <path>` CLI subcommand mounted in
    `crates/chio-cli/`.
- Public model-card registry anchored via trajectory-2 M09 lineage
  anchors. New cards published into the registry consume the existing
  anchor proof surface.
- Cross-provider equality oracle (M07) consumed as the test that two
  cards are operationally equivalent under canonical inputs. The test
  is not a property of the cards themselves; it is the externally
  reproducible procedure that two cards under the same canonical
  scenario corpus produce verdict-equivalent outputs.
- Browser path: a TypeScript helper `@chio/passkey` at
  `sdks/typescript/packages/passkey/` exposing
  `requestCapability({ rpId, audience, scopes, issuerUrl })` that
  performs the WebAuthn assertion via `navigator.credentials.get`,
  POSTs the assertion to the issuer, and returns the
  `PasskeyCapability` parsed via `parseCapabilityToken` from
  `@chio-protocol/browser`. The package holds zero key material.
- Demo HTML page at `docs/demo/passkey/index.html` doing the full flow:
  user taps the passkey, browser fetches the capability, kernel call
  is permitted, then the issuer revokes the credential and the next
  call denies within an M04 epoch.
- Threat-model rows added to
  `spec/security/chio-threat-model.v1.json` and `spec/SECURITY.md`:
  - `passkey_credential_theft`
  - `audience_confusion`
  - `weights_hash_spoof`

Out (and why):

- In-browser signing of any envelope. The M08.P3 verdict in
  `docs/trust-boundary-browser-signing.md` is dispositive. M10 explicitly
  satisfies the verdict's named evidence requirements by issuing
  audience-pinned capabilities server-side.
- Apple SEP integration. The Apple platform attestation surface is
  out of trajectory-2 scope; deferred to a hardware-custody follow-up.
- chio-embodied / IoT capabilities. Wildcard V08 territory; not
  trajectory-2.
- Browser-resident root capability authorities. Forbidden in section 1
  of the M08.P3 verdict; M10 preserves the prohibition.
- Per-tenant issuer infrastructure. The issuer is a single library
  surface in M10; multi-tenant deployment patterns are an operational
  follow-up.
- HSM-backed passkey enrollment. The WebAuthn credential lives on the
  user's authenticator (hardware key, platform authenticator);
  HSM-backed signing of the issuer's signing key is reused from the
  M03 `HybridBackend` which already documents a software-key-only path
  for this trajectory. HSM rotation is a follow-on.

## Phases

### P0: Wave-opener Cargo.lock bump

- M10.P0.T1: Pin `webauthn-rs`, `webauthn-rs-proto`, `coset` reuse,
  `base64ct` in workspace `Cargo.toml` and refresh `Cargo.lock`.
- M10.P0.T2: Open the audit doc at
  `.planning/audits/M10-hardware-custody-and-model-cards.md` with the
  starting counts (zero `chio-custody-hw`, zero `chio-weights`, zero
  WebAuthn fixtures, zero new threat IDs).
- M10.P0.T3: Append `passkey_credential_theft`, `audience_confusion`,
  and `weights_hash_spoof` rows to
  `spec/security/chio-threat-model.v1.json` and the table in
  `spec/SECURITY.md`. The M05 threat-model coverage gate consumes
  these IDs.

### P1: `chio-custody-hw` crate genesis

- M10.P1.T1: Create `crates/chio-custody-hw/` skeleton (`Cargo.toml`,
  `src/lib.rs`, `tests/`). Workspace member registration in root
  `Cargo.toml`. Crate-level lints copy `chio-attest-verify`'s
  `forbid(unsafe_code) + forbid(clippy::unwrap_used) +
  forbid(clippy::expect_used)`.
- M10.P1.T2: `PasskeyVerifier` surface in
  `crates/chio-custody-hw/src/verifier.rs` wrapping `webauthn-rs`'s
  assertion-verify primitive. `verify_assertion(challenge, assertion)
  -> Result<VerifiedAssertion, CustodyError>`. Fail-closed; every
  `Err(_)` path carries a `urn:chio:error:*` code (M01 dependency).
- M10.P1.T3: `PasskeyCapability` envelope in
  `crates/chio-custody-hw/src/capability.rs`: canonical-JSON encoding,
  five-minute fixed `exp`, audience pin, signature verifier helper.
- M10.P1.T4: Issuer service shape in
  `crates/chio-custody-hw/src/issuer.rs`: a library Axum service handler
  that receives the assertion, calls the verifier, and emits a stub
  capability (signing in P2). Round-trip integration test against a
  pinned WebAuthn assertion fixture.
- M10.P1.T5: Pinned WebAuthn fixture corpus under
  `crates/chio-custody-hw/fixtures/passkey/` (4 positive, 4 negative
  including replayed challenge, mismatched origin, expired challenge,
  malformed CBOR).
- M10.P1.T6: `urn:chio:error:custody:*` registry rows added in
  `spec/errors/registry.yaml` (M01 dependency). At minimum:
  `urn:chio:error:custody:assertion-rejected`,
  `urn:chio:error:custody:audience-mismatch`,
  `urn:chio:error:custody:replay-detected`,
  `urn:chio:error:custody:capability-expired`,
  `urn:chio:error:custody:credential-revoked`.

### P2: Capability minting and revocation cascade

- M10.P2.T1: Wire `HybridBackend` (trajectory-2 M03.P2.T2) into the
  issuer's `mint_capability` path. Capabilities sign with the kernel's
  configured `crypto_floor`. `crypto_floor=allow_classical` capabilities
  remain byte-identical to the classical case; hybrid capabilities
  follow the M03 `hybrid:` prefix discipline.
- M10.P2.T2: Replay-attack resistance: durable nonce store
  (`PasskeyNonceStore` trait + an in-memory test impl + a SQLite impl
  reusing `chio-store-sqlite`). Keyed by
  `(credential_id, challenge_nonce)`; insert-and-check-existed
  semantics. Replayed assertions reject with
  `urn:chio:error:custody:replay-detected`.
- M10.P2.T3: Revocation cascade through M04 oracle: when the issuer
  marks a credential revoked, it pushes a revocation entry into
  `chio-revocation-oracle` keyed by `(issuer_id, credential_id)`.
  Capabilities reference the credential id; the kernel rejects
  capabilities whose credential is revoked at the next M04 epoch.
- M10.P2.T4: Audience-confusion property test
  (`crates/chio-custody-hw/tests/audience_confusion.rs`): proptest
  generates capabilities for audience A and asserts that verification
  for audience B always fails. Bit-flips on the audience field MUST
  cause verification failure.
- M10.P2.T5: Kernel-side `PasskeyCapabilityVerifier` integration in
  `crates/chio-kernel/`. The verifier is a thin wrapper that delegates
  to `chio-custody-hw` and returns a `Verdict` shape consumable by the
  existing dispatch path. No `&mut self` introduced.
- M10.P2.T6: End-to-end issuer-to-kernel test: present passkey, get
  capability, call kernel, revoke at issuer, next call denies within
  the M04 epoch.

### P3: Browser flow and `@chio/passkey`

- M10.P3.T1: New TypeScript package `sdks/typescript/packages/passkey/`
  (`@chio/passkey`). `package.json` (engines, exports, peer dep on
  `@chio-protocol/browser`), `tsconfig.json`, `src/index.ts` exposing
  `requestCapability({ rpId, audience, scopes, issuerUrl })`.
- M10.P3.T2: Implement `requestCapability` performing
  `navigator.credentials.get` against an issuer-fetched challenge,
  POSTing the assertion to the issuer, and parsing the returned
  capability via `parseCapabilityToken` from `@chio-protocol/browser`.
  Zero key material is held in the browser.
- M10.P3.T3: Demo HTML at `docs/demo/passkey/index.html` plus
  `docs/demo/passkey/main.ts` driving the full flow against a pinned
  fixture capability. Includes the engineering-output banner
  (M08 demo-path discipline). Playwright headless test in
  `sdks/typescript/packages/passkey/tests/e2e.spec.ts`.
- M10.P3.T4: End-to-end revocation test: the demo page calls a stub
  kernel endpoint that returns `200` for a fresh capability and `403`
  for a revoked capability, with the revocation pushed through a
  fake `chio-revocation-oracle` test double. Asserts that revoking
  at the issuer denies the next call within an M04 epoch (one second
  in the test config).
- M10.P3.T5: Per-runtime size budget for `@chio/passkey`:
  `< 30 KB gzipped`. The package is a thin call site; if it grows past
  30 KB it is doing too much.
- M10.P3.T6: `urn:chio:error:custody:*` codes consumed in TS errors
  via the M01 LSP-driven typed-enum codegen. Errors thrown from
  `requestCapability` carry a stable code matching the registry.

### P4: `chio-weights` model card schema and `arc bind`

- M10.P4.T1: Create `crates/chio-weights/` skeleton (`Cargo.toml`,
  `src/lib.rs`, `tests/`). Workspace member registration. Crate-level
  lints match `chio-custody-hw`.
- M10.P4.T2: Model card schema at `spec/schemas/model-card.v1.json`
  plus the `ModelCard` type in `crates/chio-weights/src/card.rs`.
  Required fields enumerated in Scope; canonical-JSON encoding locked
  via vectors in `crates/chio-weights/tests/golden/`.
- M10.P4.T3: Cosign bundle helper in
  `crates/chio-weights/src/bundle.rs` consuming
  `SigstoreVerifier::verify_bundle`. The helper does not introduce a
  new trust root; it asks `chio-attest-verify` to verify the bundle
  against an `ExpectedIdentity` supplied by the caller.
- M10.P4.T4: `policy.weights_card_required` enum in `chio-policy`
  (`disabled | required | required_with_pin`). `required_with_pin`
  pins a specific issuer SAN regex. Invalid combinations
  (`required` with no issuer configured) reject at policy load.
- M10.P4.T5: Kernel binding refusal in `chio-kernel`. When the policy
  is `required` or `required_with_pin`, provider bind verifies:
  (a) the provider's loaded `weights_hash` matches a signed card,
  (b) the requested capability set is a subset of the card's
  `allowed_capability_set`,
  (c) no requested tool intersects `banned_tools`.
  Failure rejects with
  `urn:chio:error:weights:card-mismatch` /
  `urn:chio:error:weights:scope-not-subset` /
  `urn:chio:error:weights:tool-banned`.
- M10.P4.T6: `arc bind <provider> --card <path>` CLI subcommand in
  `crates/chio-cli/`. Loads the card, runs the cosign bundle verify,
  attaches the card to the provider binding context, and prints the
  resolved `(weights_hash, allowed_capability_set)` so an operator
  can sanity-check before promoting to production policy.

### P5: Cross-cutting (lineage anchoring, equivalence, threat coverage)

- M10.P5.T1: Lineage anchoring of model cards via trajectory-2 M09.
  Publishing a card to the public registry emits a lineage anchor
  proof; consumers verify the proof through the existing
  `chio-lineage` surface.
- M10.P5.T2: Cross-provider equality test
  (`crates/chio-weights/tests/equivalence.rs`): given two cards A and
  B and a canonical scenario corpus from
  `crates/chio-provider-conformance/`, the test asserts that providers
  bound under each card produce verdict-equivalent outputs at every
  scenario. The test consumes M07's verdict-equality oracle; it does
  not duplicate it.
- M10.P5.T3: Threat-model coverage gate (M05 dependency): the three
  new threat IDs (`passkey_credential_theft`, `audience_confusion`,
  `weights_hash_spoof`) MUST be marked covered by M10 fixtures and
  tests before the milestone closes. Coverage map lives at
  `spec/security/coverage.yaml` (M05 owns the file shape).
- M10.P5.T4: Audit doc final pass at
  `.planning/audits/M10-hardware-custody-and-model-cards.md` with
  closing counts (`chio-custody-hw` line count, `chio-weights` line
  count, fixture corpus size, threat-model coverage, M07 equivalence
  test green).
- M10.P5.T5: Documentation pass: a one-page narrative at
  `docs/custody/passkey-issuer.md` explaining the provenance chain
  (passkey -> issuer -> M03-signed capability -> kernel) and a
  one-page narrative at `docs/weights/model-cards.md` explaining the
  binding refusal contract. Both pages cite
  `docs/trust-boundary-browser-signing.md` and the M07 equivalence
  oracle.

## Cross-milestone interactions

- trajectory-1 M07 (`crates/chio-provider-conformance/`) verdict
  equality oracle is the operational-equivalence test for model cards.
  Consumed in P5.T2; not forked.
- trajectory-1 M08.P3 verdict (`docs/trust-boundary-browser-signing.md`)
  defines M10's scope contract. The issuer is the named server-side
  authority the verdict demanded. The capability shape satisfies the
  verdict's audience / expiry / scope requirements.
- trajectory-1 M09 (`crates/chio-attest-verify/`) cosign bundle path
  is the verifier consumed by `chio-weights`. M10 does not extend the
  Sigstore path; it asks the existing crate to verify card bundles.
- trajectory-2 M01 (`urn:chio:error:*` registry) is consumed by both
  halves; every `Err(_)` carries a stable code.
- trajectory-2 M03 (`HybridBackend`) signs `PasskeyCapability`
  envelopes. M10 capabilities are PQ-ready as soon as
  `crypto_floor=allow_hybrid` lands.
- trajectory-2 M04 (`chio-revocation-oracle`) is the revocation
  cascade for WebAuthn credential revocation. M10 does not invent
  its own surface.
- trajectory-2 M05 (threat-model-as-code) consumes the three new
  threat IDs as the coverage-gate inputs.
- trajectory-2 M07 (provider matrix) defines the scope set that
  `allowed_capability_set` is a subset of. Card schema validation
  rejects scopes not in the M07 provider matrix at card load.
- trajectory-2 M09 (lineage) anchors model cards into the public
  registry. M10 publishes; M09 owns the anchor proof surface.

## Risks and mitigations

- **WebAuthn library churn.** `webauthn-rs` 0.5 is the current line;
  the FIDO Metadata Service surface still moves. Mitigation: pin
  `webauthn-rs = "0.5"` at P0, treat MDS-format divergence between
  patch versions as a release-blocking bug, and keep the fixture
  corpus byte-pinned. The fixture file at
  `crates/chio-custody-hw/fixtures/passkey/` is the regression oracle.
- **Audience confusion.** A capability minted for audience A presented
  to audience B is the central attack the audience pin defends
  against. Mitigation: P2.T4 proptest enforces audience-bit-flip
  rejection across the full envelope; the kernel verifier rejects
  audience mismatch fail-closed.
- **Replay across issuer restarts.** A durable nonce store is
  required; an in-memory store loses replay protection on restart.
  Mitigation: the SQLite-backed `PasskeyNonceStore` is the production
  default; the in-memory store is test-only and is documented as
  such in the rustdoc.
- **Issuer-clock drift.** The capability `exp` is computed off the
  kernel clock not the issuer clock to keep verifier-side time
  monotonic. Mitigation: P1.T3 wires the kernel clock; an integration
  test in P2.T6 asserts a forged future-`exp` capability rejects
  fail-closed.
- **Weights-hash spoof.** A provider that lies about its loaded
  weights hash is the central attack `chio-weights` defends against.
  Mitigation: the kernel binding contract recomputes the hash from
  the loaded weights blob (via `chio-providers` once that surface
  lands; until then the provider-supplied hash is treated as
  attested-by-cosign-bundle and the threat ID
  `weights_hash_spoof` is marked `coverage_state: partial` per the
  M05 P5.T1 threat-model schema, with the gap documented in the
  M10 audit doc and surfaced under the Partial heading of
  `docs/security/threat-coverage.md`).
- **Descope plan for threat IDs if model-card half cuts.** D24 names
  custody (P0-P3) as the half that ships under schedule pressure.
  If P4-P5 are cut, the threat IDs `passkey_credential_theft` and
  `audience_confusion` (custody-side) close as `coverage_state:
  covered` per M05 P5.T1. `weights_hash_spoof` (model-card-side)
  flips to `coverage_state: pending` with a `deferred_to: follow-on`
  note in the audit doc; the threat-model-coverage CI gate
  (M05.P5.T4) treats `pending` as PASS only when the entry carries
  the explicit `deferred_to` field, otherwise it fails closed. This
  preserves the integrity of the trajectory-2 close gate while
  permitting the descope.
- **Cosign bundle revocation lag.** A model card's signing identity
  may be revoked after the card is published. Mitigation: the
  cosign bundle verifier consumes Rekor inclusion proofs that ride
  on the existing trajectory-1 M09 surface; the audit doc names the
  revocation re-bake cadence.
- **`policy.weights_card_required` misconfiguration.** A deployment
  that flips `required` without provisioning cards bricks provider
  bind. Mitigation: invalid policy combinations reject at policy
  load (P4.T4), not at first bind. A deployment can flip to
  `required_with_pin` only after at least one card matching the pin
  loads cleanly.
- **Browser cold-start cost.** The `@chio/passkey` package is a thin
  wrapper, but `navigator.credentials.get` adds platform-side
  latency outside the SDK's control. Mitigation: the demo page
  documents the expected latency envelope; the size budget keeps
  the SDK contribution to first-paint negligible.

## Success criteria

- `cargo test -p chio-custody-hw` green; replay-attack resistance
  test, audience-confusion proptest, and pinned WebAuthn fixture
  corpus all pass.
- `cargo test -p chio-weights` green; model card canonical-JSON
  vectors lock the schema; cosign bundle verify path consumes
  `chio-attest-verify`.
- `arc bind <provider> --card <path>` subcommand in `chio-cli`
  succeeds against a fixture provider + card; refusal paths
  (`urn:chio:error:weights:card-mismatch`,
  `urn:chio:error:weights:scope-not-subset`,
  `urn:chio:error:weights:tool-banned`) tested.
- End-to-end revocation test green: passkey -> issuer-minted
  capability -> kernel call permitted -> revoke at issuer ->
  next call denies within the M04 epoch.
- `@chio/passkey` published to npm under the existing
  `@chio` org with semver, `< 30 KB gzipped`, demo page renders
  the full flow.
- `spec/security/chio-threat-model.v1.json` carries
  `passkey_credential_theft`, `audience_confusion`, and
  `weights_hash_spoof` rows; M05's threat-model coverage gate marks
  them covered.
- `crates/chio-provider-conformance/`-driven cross-provider
  equivalence test (P5.T2) green for at least one card pair on the
  canonical scenario corpus.
- `policy.weights_card_required` present in `chio-policy`; invalid
  combinations reject at load time.
- Audit doc at
  `.planning/audits/M10-hardware-custody-and-model-cards.md` closes
  with the measured before / after counts.
