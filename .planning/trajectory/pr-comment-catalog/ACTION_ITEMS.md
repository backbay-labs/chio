# Unresolved Review Threads

Fetched from GitHub GraphQL on 2026-04-27. Each item is a currently unresolved review thread on `bb-connor/arc` PRs `#13` through `#140`. Comment bodies are truncated to ~200 chars; click the thread link for full history and follow-ups.

## Summary

- Currently unresolved threads: **232**
- On PRs `#13`-`#86`: **102**
- On PRs `#87`-`#140`: **130**
- PRs with at least one unresolved thread: **95**

## By PR

### PR #13 -- `test: harden production fuzzing baseline`

- **`crates/chio-guards/src/shell_command.rs:267`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/13#discussion_r3143049257)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Skip sudo VAR=value assignments before executable resolution** In `executable_rm_index`, the `sudo` branch only c...

### PR #15 -- `docs(spec): add spec/schemas/COVERAGE.md audit checklist [M01.P1.T1]`

- **`spec/schemas/COVERAGE.md:225`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/15#discussion_r3142804095)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Fix incorrect current counts for receipt/capability vectors** Section C says the `Current` column reflects what i...

### PR #16 -- `feat(spec): add capability-token, grant, and revocation wire schemas [M01.P1.T2]`

- **`spec/schemas/chio-wire/v1/capability/token.schema.json:25`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/16#discussion_r3142814743)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Accept prefixed public keys in capability token schema** `CapabilityToken` uses `PublicKey` serde serialization,...

- **`spec/schemas/chio-wire/v1/capability/token.schema.json:60`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/16#discussion_r3142814744)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Accept prefixed signatures in capability token schema** `Signature` serde output is algorithm-prefixed for non-Ed...

- **`spec/schemas/chio-wire/v1/capability/token.schema.json:26`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/16#discussion_r3142817251)  
  > ### Key/signature patterns reject FIPS algorithm tokens **Medium Severity** <!-- DESCRIPTION START --> The `issuer`, `subject`, `delegator`, and `delegatee` fields use `pattern: "^[0-9a-f]{64}$"` and...

- **`spec/schemas/chio-wire/v1/capability/token.schema.json:206`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/16#discussion_r3142817252)  
  > ### Grant type definitions duplicated across two schema files **Low Severity** <!-- DESCRIPTION START --> Six `$defs` — `toolGrant`, `resourceGrant`, `promptGrant`, `operation`, `monetaryAmount`, and...

### PR #17 -- `test(chio-kernel-core): name five evaluate invariants [M03.P1.T3]`

- **`crates/chio-kernel-core/tests/property_evaluate.rs:286`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/17#discussion_r3142816112)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Fail fast on unexpected matcher errors** This branch treats `resolve_matching_grants` failures as a successful pr...

- **`crates/chio-kernel-core/tests/property_evaluate.rs:172`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/17#discussion_r3142816113)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Ensure expired-capability invariant uses in-scope requests** The request `(server_id, tool_name)` is sampled inde...

- **`crates/chio-kernel-core/tests/property_evaluate.rs:312`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/17#discussion_r3142820366)  
  > ### BTreeSet deduplicates matched grants masking multiset differences **Low Severity** <!-- DESCRIPTION START --> Invariant 3 collects matched-grant keys into a `BTreeSet`, which deduplicates entries...

### PR #18 -- `test(chio-core-types): name five capability algebra invariants [M03.P1.T2]`

- **`crates/chio-core-types/tests/property_capability_algebra.rs:313`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/18#discussion_r3142816281)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Fail the property when link signing fails** `delegation_depth_bounded_by_root` returns `Ok(())` when `DelegationL...

- **`crates/chio-core-types/tests/property_capability_algebra.rs:313`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/18#discussion_r3142818339)  
  > ### Silent test pass on signing failure masks bugs **Medium Severity** <!-- DESCRIPTION START --> When `DelegationLink::sign` fails, `return Ok(())` silently counts the test case as passing instead of...

### PR #19 -- `feat(spec): add receipt record and inclusion-proof wire schemas [M01.P1.T3]`

- **`spec/schemas/chio-wire/v1/receipt/record.schema.json:98`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/19#discussion_r3142828169)  
  > ### Signature minLength inconsistent with description **Low Severity** <!-- DESCRIPTION START --> The `signature` constraint sets `minLength` to 96, but the description states Ed25519 signatures are e...

- **`spec/schemas/chio-wire/v1/receipt/record.schema.json:85`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/19#discussion_r3142828294)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Tighten kernel_key regex to match accepted key encodings** `kernel_key` currently accepts any `p256:`/`p384:` hex...

- **`spec/schemas/chio-wire/v1/receipt/record.schema.json:96`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/19#discussion_r3142828295)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Reject impossible signature lengths in receipt schema** The `signature` pattern allows bare hex strings of any le...

### PR #20 -- `test(chio-credentials): name four passport lifecycle invariants [M03.P1.T4]`

- **`crates/chio-credentials/tests/property_passport.rs:294`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/20#discussion_r3142831022)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Exercise active-lifecycle gate instead of state tautology** This invariant never reaches the cross-issuer `requir...

- **`crates/chio-credentials/tests/property_passport.rs:319`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/20#discussion_r3142831023)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Validate monotonicity against crate behavior, not local helper** This property is self-referential: `forward_ok`...

- **`crates/chio-credentials/tests/property_passport.rs:347`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/20#discussion_r3142834154)  
  > ### Invariant 3 test is tautological, exercises no production code **Low Severity** <!-- DESCRIPTION START --> The `lifecycle_state_transitions_monotone` test is a mathematical tautology that can neve...

### PR #21 -- `test(chio-policy): name four merge/evaluate invariants [M03.P1.T5]`

- **`crates/chio-policy/tests/property_evaluate.rs:233`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/21#discussion_r3142831900)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Validate deny override on merged policy chain** This property never exercises predecessor/successor composition:...

### PR #22 -- `ci: tier proptest case count by lane (PR=256, nightly=4096) [M03.P1.T6]`

- **`.github/workflows/nightly.yml:29`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/22#discussion_r3142839365)  
  > ### Proptest tiering bypassed by hardcoded with_cases **High Severity** <!-- DESCRIPTION START --> The four target proptest suites set explicit case counts via `ProptestConfig::with_cases(48)` and `wi...

### PR #25 -- `feat(supply-chain): bootstrap cargo-vet workspace [M09.P1.T1]`

- **`supply-chain/config.toml:131`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/25#discussion_r3142845344)  
  > ### 21 workspace crates missing from cargo-vet policy config **Medium Severity** <!-- DESCRIPTION START --> The `config.toml` policy section only contains 42 `[policy.chio-*]` entries with `audit-as-c...

### PR #26 -- `feat(spec): add trust-control wire schemas (lease, heartbeat, terminate, attestation) [M01.P1.T4.b]`

- **`spec/schemas/chio-wire/v1/trust-control/lease.schema.json:52`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/26#discussion_r3142847185)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Correct lease timestamp unit to seconds** `leaseExpiresAt` is documented here as a Unix-millisecond timestamp, bu...

- **`spec/schemas/chio-wire/v1/trust-control/lease.schema.json:57`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/26#discussion_r3142851189)  
  > ### Lease timestamps described as milliseconds but are seconds **High Severity** <!-- DESCRIPTION START --> The `leaseExpiresAt` and `termStartedAt` fields in `lease.schema.json`, and similar timestam...

### PR #28 -- `chore(deny): Phase 1 hardened deny.toml with cargo-deny 0.19 schema [M09.P1.T4]`

- **`deny.toml:48`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/28#discussion_r3142866284)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Keep MPL-2.0 crate-scoped as intended** Adding `"MPL-2.0"` to the global `licenses.allow` list broadens acceptanc...

- **`deny.toml:63`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/28#discussion_r3142870711)  
  > ### Redundant per-crate MPL-2.0 exception contradicts allow-list **Medium Severity** <!-- DESCRIPTION START --> The per-crate exception for `webpki-roots` adds `MPL-2.0`, but `MPL-2.0` is already in t...

### PR #29 -- `feat(spec): add provenance wire schemas (stamp, context, attestation-bundle, verdict-link) [M01.P1.T4.c]`

- **`spec/schemas/chio-wire/v1/provenance/attestation-bundle.schema.json:36`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/29#discussion_r3142865624)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Include full attestation fields in bundle statements** The statement item schema is declared with `additionalProp...

- **`spec/schemas/chio-wire/v1/provenance/verdict-link.schema.json:12`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/29#discussion_r3142865626)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Enforce verdict-specific reason and guard requirements** This schema only requires `verdict`, `requestId`, `chain...

- **`spec/schemas/chio-wire/v1/provenance/attestation-bundle.schema.json:82`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/29#discussion_r3142869207)  
  > ### Attestation bundle statements drop two optional fields **High Severity** <!-- DESCRIPTION START --> The `statements` item schema sets `additionalProperties: false` but omits `workload_identity` an...

### PR #30 -- `chore(supply-chain): certify residual unaudited deps (safe-to-deploy) [M09.P1.T3]`

- **`supply-chain/audits.toml:158`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/30#discussion_r3142870354)  
  > ### Audited crates retain redundant exemption entries in config **Low Severity** <!-- DESCRIPTION START --> All 26 newly audited crate@version pairs (e.g. `anyhow` 1.0.102, `bitflags` 2.11.0, `hashbro...

### PR #32 -- `feat(spec): extend chio-http schemas (stream-frame, session-init, session-resume, error-envelope) [M01.P1.T5]`

- **`spec/schemas/chio-http/v1/stream-frame.schema.json:45`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/32#discussion_r3142872463)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Nest related-task metadata under params** The schema places `_meta` at the top level, but `queue_tool_stream_chun...

- **`spec/schemas/chio-http/v1/session-resume.schema.json:60`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/32#discussion_r3142872466)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Describe lifecycle timestamps in milliseconds** The lifecycle timestamp descriptions say "seconds", but these fie...

- **`spec/schemas/chio-http/v1/stream-frame.schema.json:54`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/32#discussion_r3142872847)  
  > ### `_meta` placed at wrong nesting level in schema **High Severity** <!-- DESCRIPTION START --> The `_meta` field is defined as a top-level property (sibling of `jsonrpc`, `method`, `params`), but th...

- **`spec/schemas/chio-http/v1/session-resume.schema.json:55`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/32#discussion_r3142872848)  
  > ### Session state enum values use wrong case **High Severity** <!-- DESCRIPTION START --> The `state` enum values are lowercase (`"initializing"`, `"ready"`, etc.) based on the `as_str()` method, but...

### PR #34 -- `feat(spec-validate): add chio-spec-validate crate + xtask validate-scenarios [M01.P1.T6]`

- **`Cargo.toml:157`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/34#discussion_r3142878423)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Enable JSON Schema reference resolution** `chio-spec-validate` inherits `jsonschema = { default-features = false...

- **`xtask/src/main.rs:307`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/34#discussion_r3142878424)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Fail on unrecognized scenario $schema URIs** When a scenario provides a `$schema` value that does not match the h...

- **`xtask/src/main.rs:313`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/34#discussion_r3142881906)  
  > ### Scenario file read and parsed twice unnecessarily **Low Severity** <!-- DESCRIPTION START --> `validate_scenarios` reads and parses each scenario file into a `serde_json::Value` to extract the `$s...

- **`xtask/src/main.rs:312`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/34#discussion_r3142881907)  
  > ### Schema URI-to-path mapping mismatches existing `$id` convention **Medium Severity** <!-- DESCRIPTION START --> The `SCHEMA_URI_PREFIX` strip-and-join logic assumes `$schema` URIs in scenarios will...

### PR #39 -- `ci(supply-chain): wire cargo-deny check into ci.yml [M09.P1.T9]`

- **`.github/workflows/ci.yml:316`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/39#discussion_r3142881621)  
  > ### Missing `sources` check omits registry/git enforcement **Medium Severity** <!-- DESCRIPTION START --> The `cargo-deny` CI job is missing the `cargo deny check sources` step. This check is required...

- **`.github/workflows/ci.yml:313`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/39#discussion_r3142881800)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Add cargo-deny sources check to the CI gate** This job enforces advisories and licenses but never runs `cargo den...

### PR #40 -- `ci: document required-check inventory + add concurrency group [M09.P1.T11]`

- **`.github/workflows/ci.yml:14`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/40#discussion_r3142883192)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Align required-check inventory with emitted check names** The new required-check inventory lists `check` and `msr...

### PR #42 -- `feat(vectors): grow canonical corpus to 20 cases + land vectors_oracle [M01.P2.T1]`

- **`crates/chio-conformance/tests/vectors_oracle.rs:137`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/42#discussion_r3142892759)  
  > ### Unreachable byte-equality check after string comparison **Low Severity** <!-- DESCRIPTION START --> The `as_bytes()` comparison on lines 132–137 is dead code. In Rust, `String` vs `&str` equality...

### PR #43 -- `feat(release): wrap release-binaries builds with cargo-auditable [M09.P2.T1]`

- **`.github/workflows/release-binaries.yml:139`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/43#discussion_r3142892200)  
  > **<sub><sub>![P0 Badge](https://img.shields.io/badge/P0-red?style=flat)</sub></sub> Avoid `cross auditable build` in release workflow** `cross` 0.2.5 does not treat `auditable` as a cross-executed bui...

- **`.github/workflows/release-binaries.yml:139`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/43#discussion_r3142894176)  
  > ### `cross auditable build` unsupported in cross v0.2.5 **High Severity** <!-- DESCRIPTION START --> `cross` v0.2.5 does not support custom cargo subcommands like `auditable`. When `cross auditable bu...

### PR #44 -- `feat(sbom): emit CycloneDX 1.6 SBOMs via pinned syft v1.18.1 [M09.P2.T2]`

- **`.github/workflows/release-binaries.yml:158`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/44#discussion_r3142897955)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Pin installer script to immutable syft ref** The workflow claims syft is pinned to `v1.18.1`, but this step execu...

- **`.github/workflows/release-binaries.yml:158`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/44#discussion_r3142898745)  
  > ### Unpinned install script fetched from mutable main branch **Medium Severity** <!-- DESCRIPTION START --> The syft `install.sh` is fetched from the mutable `main` branch (`raw.githubusercontent.com/...

- **`infra/sbom/syft.yaml:32`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/44#discussion_r3142898746)  
  > ### Syft config uses unrecognized nested YAML keys **Low Severity** <!-- DESCRIPTION START --> The `package.cataloger.enabled` and `package.cataloger.scope` keys don't match syft's documented configur...

### PR #45 -- `feat(vectors): grow manifest corpus to 20 cases [M01.P2.T2]`

- **`tests/bindings/vectors/manifest/v1.json:374`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/45#discussion_r3142897620)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Update fixture generator for added manifest vectors** Adding 15 new cases to `tests/bindings/vectors/manifest/v1....

- **`tests/bindings/vectors/manifest/v1.json:1465`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/45#discussion_r3142904375)  
  > ### Fixture generator and checked-in JSON case count diverge **Medium Severity** <!-- DESCRIPTION START --> After this commit the checked-in `manifest/v1.json` contains 20 cases, but `manifest_cases()...

### PR #46 -- `feat(slsa): wire slsa-github-generator v2.1.0 for SLSA L2 provenance [M09.P2.T3]`

- **`.github/workflows/slsa.yml:66`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/46#discussion_r3142898932)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Provide release tag to the SLSA upload step** `upload-assets: true` alone is not enough in this `workflow_run`-tr...

- **`.github/workflows/slsa.yml:21`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/46#discussion_r3142900224)  
  > ### SLSA workflow never fires on tag-triggered releases **High Severity** <!-- DESCRIPTION START --> The `branches` filter on the `workflow_run` trigger (`[main, project/roadmap-04-25-2026]`) only mat...

### PR #47 -- `feat(vectors): grow hashing corpus to 20 cases [M01.P2.T3]`

- **`tests/bindings/vectors/hashing/v1.json:25`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/47#discussion_r3142903127)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Sync hashing fixture generator with expanded corpus** This commit expands `tests/bindings/vectors/hashing/v1.json...

- **`tests/bindings/vectors/hashing/v1.json:121`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/47#discussion_r3142909054)  
  > ### Hashing fixture parity test will fail **High Severity** <!-- DESCRIPTION START --> Growing this corpus to 20 cases without correspondingly expanding the Rust `hashing_vector_fixture()` generator i...

### PR #48 -- `feat(vectors): grow signing corpus to 22 cases (utf8 14 + json 8) [M01.P2.T4]`

- **`tests/bindings/vectors/signing/v1.json:179`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/48#discussion_r3142913437)  
  > ### Per-case seed overrides break Rust signing round-trip test **High Severity** <!-- DESCRIPTION START --> New vectors with per-case `signing_key_seed_hex` overrides (e.g. `utf8_payload_with_all_zero...

### PR #49 -- `feat(vectors): grow receipt corpus to 20 cases (verify_only tags) [M01.P2.T5]`

- **`tests/bindings/vectors/receipt/v1.json:996`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/49#discussion_r3142922986)  
  > ### New receipt vectors unverified by round-trip test **Medium Severity** <!-- DESCRIPTION START --> The receipt round-trip test (`receipt_fixture_cases_round_trip_through_public_api`) calls `receipt_...

### PR #50 -- `feat(vectors): grow capability corpus to 20 cases (verify_only tags) [M01.P2.T6]`

- **`tests/bindings/vectors/capability/v1.json:686`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/50#discussion_r3142926333)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Keep shared vector expectation depth-agnostic** This case sets `delegation_chain_valid` to `false` only under a m...

### PR #52 -- `test(spec): assert vector domain to schema coverage [M01.P2.T8]`

- **`crates/chio-conformance/tests/vectors_schema_pair.rs:156`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/52#discussion_r3142935484)  
  > ### Panicking helper defeats failure-collection in loop **Low Severity** <!-- DESCRIPTION START --> `every_mapping_entry_resolves_to_existing_files` collects missing-file errors into a `failures` vec...

### PR #53 -- `chore(formal): pin Apalache 0.50.1 installer + RevocationPropagation MC cfg [M03.P3.T1]`

- **`formal/tla/MCRevocationPropagation.cfg:5`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/53#discussion_r3142943822)  
  > ### Missing `DEPTH_MAX` constant in model checking config **Medium Severity** <!-- DESCRIPTION START --> The `CONSTANTS` block is missing `DEPTH_MAX = 4`. The planning document explicitly specifies th...

- **`tools/install-apalache.sh:47`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/53#discussion_r3142943825)  
  > ### Missing pipeline error guard aborts script under pipefail **High Severity** <!-- DESCRIPTION START --> The version-detection pipeline on lines 46–47 lacks a `|| true` or `|| echo ""` fallback. Bec...

### PR #54 -- `test(kani): prove scope intersection associative + revocation predicate idempotent [M03.P2.T1]`

- **`crates/chio-kernel-core/src/kani_public_harnesses.rs:421`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/54#discussion_r3142943511)  
  > ### Kani proof asserts trivially true pure-function determinism **Low Severity** <!-- DESCRIPTION START --> Three of the four assertions in `verify_revocation_predicate_idempotent` are vacuous. `asser...

### PR #55 -- `feat(spec-codegen): scaffold chio-spec-codegen + xtask codegen rust [M01.P3.T1]`

- **`xtask/src/main.rs:565`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/55#discussion_r3142960528)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Check every generated file in codegen drift mode** In `--check` mode this path validates only `chio_wire_v1.rs` a...

- **`crates/chio-core-types/tests/_generated_check.rs:57`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/55#discussion_r3142960529)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Enforce full generated header, not just its first line** This check only requires files to start with `HEADER_PRE...

### PR #56 -- `feat(attest-verify): land chio-attest-verify with AttestVerifier trait + SigstoreVerifier [M09.P3.T1]`

- **`crates/chio-attest-verify/src/sigstore.rs:376`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/56#discussion_r3142968181)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Decode DER OIDC issuer before string comparison** When the OIDC issuer extension is DER-encoded (the standard X.5...

- **`crates/chio-attest-verify/src/sigstore.rs:218`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/56#discussion_r3142968183)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Avoid calling Runtime::block_on inside async contexts** This synchronous verifier method invokes `self.runtime.bl...

- **`crates/chio-attest-verify/src/sigstore.rs:98`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/56#discussion_r3142974715)  
  > ### Runtime `block_on` panics inside async context **High Severity** <!-- DESCRIPTION START --> The `SigstoreVerifier` builds an internal `current_thread` tokio runtime and calls `self.runtime.block_o...

- **`crates/chio-attest-verify/src/sigstore.rs:543`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/56#discussion_r3142974717)  
  > ### Unreachable `SigstoreIdentityPolicy` re-export from private module **Low Severity** <!-- DESCRIPTION START --> `SigstoreIdentityPolicy` is declared as a `pub use` re-export inside the private `mod...

### PR #57 -- `test(kani): prove single-step delegation attenuation [M03.P2.T2]`

- **`crates/chio-kernel-core/src/kani_public_harnesses.rs:539`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/57#discussion_r3142968314)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Exercise runtime subset logic in delegation-step proof** `verify_delegation_chain_step` models key attenuation di...

### PR #58 -- `docs(formal): scaffold OWNERS.md template with TBD-primary/TBD-backup [M03.P3.T7]`

- **`formal/OWNERS.md:33`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/58#discussion_r3142968121)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Fix Apalache pin path in ownership instructions** The responsibilities section points owners to `scripts/install-...

### PR #60 -- `feat(spec-codegen): wire xtask codegen --lang go via oapi-codegen + regen-types.sh [M01.P3.T4]`

- **`xtask/src/main.rs:659`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/60#discussion_r3142990972)  
  > ### Go shell failure wrapped in Rust-specific `Typify` error **Low Severity** <!-- DESCRIPTION START --> The `codegen_go` function reports `regen-types.sh` script failures as `CodegenError::Typify`. T...

- **`sdks/go/chio-go-http/scripts/regen-types.sh:82`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/60#discussion_r3142990973)  
  > ### Dirty schema detection misses staged changes **Low Severity** <!-- DESCRIPTION START --> The `git diff --quiet` command, which determines the `-dirty` suffix for the schema SHA, only checks unstag...

- **`sdks/go/chio-go-http/scripts/regen-types.sh:82`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/60#discussion_r3142990974)  
  > ### Schema SHA stamp ties output to git history not content **Medium Severity** <!-- DESCRIPTION START --> The header embeds the SHA returned by `git log -1 -- spec/schemas/chio-wire/v1`, so the gener...

- **`xtask/src/main.rs:681`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/60#discussion_r3142990976)  
  > ### `--check` mutates `types.go` before diffing **Medium Severity** <!-- DESCRIPTION START --> `codegen_go(check_only=true)` runs the regen script unconditionally, which overwrites `sdks/go/chio-go-ht...

- **`sdks/go/chio-go-http/types.go:99`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/60#discussion_r3142990977)  
  > ### Bare-name enum constants pollute package namespace **Medium Severity** <!-- DESCRIPTION START --> Several generated enum constants are emitted without a type-name prefix and become exported packag...

- **`sdks/go/chio-go-http/scripts/regen-types.sh:179`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/60#discussion_r3142990978)  
  > ### oneOf+null inline merge keeps `title` despite comment **Low Severity** <!-- DESCRIPTION START --> The inline-merge step in the Python preprocessor advertises that it excludes `$schema`, `$id`, and...

### PR #61 -- `docs(formal): add MAPPING.md + check-mapping.sh cross-ref gate [M03.P3.T5]`

- **`scripts/check-mapping.sh:112`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/61#discussion_r3142986117)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Match mapping entries against table rows** The gate currently treats any backtick-wrapped occurrence of a propert...

- **`formal/MAPPING.md:38`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/61#discussion_r3142992287)  
  > ### Prose backtick mention defeats fail-closed gate for future invariant **Medium Severity** <!-- DESCRIPTION START --> The prose on this line contains `` `RevocationEventuallySeen` `` in backtick-wra...

- **`scripts/check-mapping.sh:97`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/61#discussion_r3142992290)  
  > ### Awk parser silently misses harness on intervening blank line **Medium Severity** <!-- DESCRIPTION START --> The awk parser sets `want = 1` on seeing `#[kani::proof]`, then unconditionally processe...

### PR #64 -- `formal: add RevocationEventuallySeen liveness with WF on Propagate [M03.P3.T3]`

- **`formal/tla/RevocationPropagation.tla:246`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/64#discussion_r3142993570)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Avoid relying on unsupported WF_vars fairness** The new `Spec` fairness conjunct `WF_vars(\E m \in pending : Prop...

- **`formal/issue-templates/liveness-counterexample.md:58`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/64#discussion_r3142993572)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Use temporal checking flag for liveness property** The counterexample template instructs running Apalache with `-...

### PR #66 -- `ci(formal): add Apalache PR + liveness lanes [M03.P3.T4]`

- **`.github/workflows/nightly.yml:110`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/66#discussion_r3142998135)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Use --temporal for the liveness property check** `RevocationEventuallySeen` is defined as a temporal formula (`~>...

- **`.github/workflows/nightly.yml:110`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/66#discussion_r3142998192)  
  > ### Wrong Apalache flag for temporal liveness property **High Severity** <!-- DESCRIPTION START --> The nightly liveness job uses `--inv=RevocationEventuallySeen`, but `RevocationEventuallySeen` is a...

### PR #67 -- `test(chio-kernel-core): prove budget checked-add no partial commit on overflow [M03.P2.T4]`

- **`crates/chio-kernel-core/src/kani_public_harnesses.rs:966`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/67#discussion_r3143002205)  
  > ### Duplicate overflow-arm assertion with misleading comment **Low Severity** <!-- DESCRIPTION START --> The `Err(ModelBudgetError::Overflow)` arm in Phase 2 includes a duplicate `assert_eq!(overflow_...

### PR #68 -- `feat(spec-codegen): wire xtask codegen --lang python via datamodel-code-generator [M01.P3.T2]`

- **`xtask/src/main.rs:1256`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/68#discussion_r3143010896)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Re-export generated models from package root** `build_python_top_init()` says callers can do `from chio_sdk._gene...

### PR #71 -- `ci(formal): wall-clock Kani harnesses + lane-driven PR/nightly jobs [M03.P2.T6]`

- **`.github/workflows/nightly.yml:164`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/71#discussion_r3143021662)  
  > ### Nightly Kani job missing RUSTFLAGS debuginfo optimization **Low Severity** <!-- DESCRIPTION START --> The `kani-public-pr` job in `ci.yml` sets `RUSTFLAGS: "${{ env.CHIO_CI_RUSTFLAGS }} -C debugin...

### PR #72 -- `ci(formal): scope PR Kani run to changed harnesses [M03.P2.T7]`

- **`scripts/kani-changed-harnesses.sh:206`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/72#discussion_r3143030538)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Treat deletion-only harness edits as proof-relevant** When the PR changes `kani_public_harnesses.rs` by deleting...

- **`scripts/kani-changed-harnesses.sh:245`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/72#discussion_r3143035964)  
  > ### Range attribution misses harnesses that depend on changed helpers **Medium Severity** <!-- DESCRIPTION START --> The range intersection algorithm in `RANGE_INTERSECT_PY` attributes all lines betwe...

- **`scripts/kani-changed-harnesses.sh:208`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/72#discussion_r3143035965)  
  > ### Pure deletions in harness source skip all verification **Medium Severity** <!-- DESCRIPTION START --> When only lines are deleted from the harness source file (no additions), all diff hunks have `...

### PR #73 -- `ci(supply-chain): cosign sign sidecar OCI image by digest [M09.P3.T2]`

- **`docs/install/PUBLISHING.md:314`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/73#discussion_r3143034423)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Expand verify regex to cover workflow_dispatch refs** The documented `cosign verify` command only accepts identit...

### PR #74 -- `docs(coord): add M06 attest-verify migration tracking doc [M09.P3.T6]`

- **`docs/coordination/m06-attest-verify-migration.md:235`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/74#discussion_r3143034863)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Replace unsatisfiable sigstore dependency gate** The close condition `cargo tree -p chio-guard-registry | grep -q...

### PR #75 -- `ci(supply-chain): cosign sign-blob for PyPI + npm releases + VERIFY.md [M09.P3.T4]`

- **`.github/workflows/release-pypi.yml:424`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/75#discussion_r3143041632)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Gate PyPI release attachments on publish success** The new `release-attest` job only depends on `plan` and `build...

- **`.github/workflows/release-npm.yml:468`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/75#discussion_r3143041637)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Gate npm release attachments on publish success** As written, `release-attest` runs after `build` without waiting...

### PR #76 -- `fuzz: add attest_verify target + empty.bin seed [M09.P3.T5]`

- **`fuzz/Cargo.toml:44`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/76#discussion_r3143040470)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Register attest_verify in the fuzz target map** This adds the `attest_verify` fuzz binary, but there is no corres...

### PR #77 -- `ci(supply-chain): cosign sign-blob release-binaries archives [M09.P3.T3]`

- **`docs/install/PUBLISHING.md:428`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/77#discussion_r3143040469)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Include workflow_dispatch refs in verification regex** The new `cosign verify-blob` recipe only accepts `@refs/ta...

### PR #79 -- `test(fuzz): add jwt_vc_verify libFuzzer target with smoke infra [M02.P1.T1.a]`

- **`crates/chio-credentials/src/fuzz.rs:63`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/79#discussion_r3143712720)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Exercise schema checks with verifiable JWTs** This target always calls `verify_chio_passport_jwt_vc_json` with ar...

- **`fuzz/tests/smoke.rs:57`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/79#discussion_r3143717811)  
  > ### Smoke test silently passes without exercising any seeds **Medium Severity** <!-- DESCRIPTION START --> `each_seed` silently returns when the corpus directory is missing, empty, or unreadable, so `...

- **`fuzz/corpus/jwt_vc_verify/near_valid_jwt.bin:1`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/79#discussion_r3143717814)  
  > ### Trailing newline in seed prevents reaching deeper code paths **Low Severity** <!-- DESCRIPTION START --> The `near_valid_jwt.bin` file ends with a trailing newline (the diff lacks a `\ No newline...

### PR #81 -- `feat(replay): golden writer for NDJSON receipts + JSON checkpoint + hex root [M04.P1.T3]`

- **`tests/replay/src/golden_writer.rs:279`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/81#discussion_r3143739206)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Use shared RFC8785 canonicalizer for golden JSON bytes** This writer introduces a second canonicalization path (`...

- **`tests/replay/src/golden_writer.rs:244`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/81#discussion_r3143739210)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Make commit transactional across all three golden artifacts** `commit` renames each file into place one-by-one, s...

### PR #82 -- `feat(replay): author 50 fixture manifests across 10 families [M04.P1.T5]`

- **`tests/replay/fixtures/deny_expired/03_clock_skew_neg.json:11`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/82#discussion_r3143747592)  
  > ### Intent contradicts failure class for clock-skew fixture **Low Severity** <!-- DESCRIPTION START --> The `intent` describes a clock evaluated "one second before the capability's `notBefore`", which...

### PR #83 -- `test(fuzz): add oid4vp_presentation libFuzzer target [M02.P1.T1.b]`

- **`fuzz/corpus/oid4vp_presentation/near_valid_vp.bin:1`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/83#discussion_r3143756721)  
  > ### Corpus seed uses wrong JSON field name convention **Medium Severity** <!-- DESCRIPTION START --> The `near_valid_vp.bin` seed's base64-decoded JWT payload uses snake_case JSON keys (`vp_token`, `p...

### PR #84 -- `feat(replay): golden reader + raw byte-comparison harness [M04.P1.T4]`

- **`tests/replay/src/golden_reader.rs:201`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/84#discussion_r3143752218)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Enforce a single trailing LF in receipts** This check only verifies that the last byte is `\n`, so a corrupted `r...

- **`tests/replay/src/golden_reader.rs:56`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/84#discussion_r3143753472)  
  > ### Duplicated contract constants risk writer-reader desync **Low Severity** <!-- DESCRIPTION START --> Five constants that define the on-disk format contract (`ROOT_LEN`, `ROOT_HEX_LEN`, `RECEIPTS_FI...

### PR #86 -- `feat(replay): wire LC_ALL=C deterministic fs iteration into driver [M04.P1.T7]`

- **`tests/replay/src/fs_iter.rs:187`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/86#discussion_r3143769974)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Normalize separators before cross-platform path sorting** `sort_paths` currently defines ordering by each path's...

- **`tests/replay/src/driver.rs:243`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/86#discussion_r3143770946)  
  > ### Exported function list_scenario_inputs is never called **Low Severity** <!-- DESCRIPTION START --> `list_scenario_inputs` is defined as a `pub` function and described as "the load-bearing wire-up...

### PR #88 -- `test(fuzz): add anchor_bundle_verify libFuzzer target [M02.P1.T2]`

- **`fuzz/Cargo.toml:54`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/88#discussion_r3143806353)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Add target-map entry for new fuzz target** Registering `anchor_bundle_verify` only in `fuzz/Cargo.toml` leaves it...

### PR #91 -- `test(fuzz): add acp_envelope_decode libFuzzer target [M02.P1.T3.c]`

- **`fuzz/Cargo.toml:69`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/91#discussion_r3143906002)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Add target-map entry for new ACP fuzz target** `acp_envelope_decode` is registered as a new fuzz binary here, but...

- **`crates/chio-acp-edge/src/fuzz.rs:144`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/91#discussion_r3143907207)  
  > ### Capability token uses expired timestamps from 2023 **Low Severity** <!-- DESCRIPTION START --> The comment on lines 141–142 claims "Fixed timestamps so the capability is always valid for the durat...

### PR #94 -- `feat(packaging): wire chio C++ SDK family for private registry publish`

- **`tools/vcpkg-overlay/ports/chio-cpp/portfile.cmake:11`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/94#discussion_r3144022628)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Use cpp/v tag in vcpkg port source ref** This port fetches sources from `REF "v${VERSION}"`, but the release work...

### PR #98 -- `ci(fuzz): extend fuzz.yml matrix with eleven new Phase-1 targets [M02.P1.T6]`

- **`.github/workflows/fuzz.yml:95`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/98#discussion_r3144065711)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Include native fuzz runs in budget enforcement** This job relies on `scripts/check-fuzz-budget.sh` as a hard gate...

- **`.github/workflows/fuzz.yml:137`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/98#discussion_r3144065713)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Prevent non-selected matrix jobs from continuing** The forced-target skip step only echoes and exits `0`, which m...

- **`.github/workflows/fuzz.yml:137`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/98#discussion_r3144069237)  
  > ### Forced-target skip step doesn't prevent subsequent steps **Medium Severity** <!-- DESCRIPTION START --> The "Skip when forced target does not match" step uses `exit 0` to signal skipping, but in G...

- **`.github/workflows/fuzz.yml:95`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/98#discussion_r3144069239)  
  > ### Budget script omits fuzz.yml from minute accounting **High Severity** <!-- DESCRIPTION START --> The comment on line 94 claims `scripts/check-fuzz-budget.sh` "counts every fuzz workflow (cflite_pr...

### PR #99 -- `docs(fuzzing): author continuous.md runbook [M02.P1.T7]`

- **`docs/fuzzing/continuous.md:77`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/99#discussion_r3144073758)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Remove unsupported `fuzz: full` label instruction** This runbook says adding a `fuzz: full` PR label runs all tar...

- **`docs/fuzzing/continuous.md:163`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/99#discussion_r3144073761)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Run smoke-test command from the fuzz workspace** The smoke-test snippet omits `cd fuzz`, unlike the other local c...

### PR #101 -- `test(fuzz): add receipt_log_replay libFuzzer target [M02.P1.T8]`

- **`fuzz/corpus/receipt_log_replay/single_receipt.bin:1`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/101#discussion_r3144093823)  
  > ### Corpus seeds fail to decode as ChioReceipt **Medium Severity** <!-- DESCRIPTION START --> The structured corpus seeds omit required `ChioReceipt` fields (`id`, `tool_server`, `tool_name`, `action`...

- **`fuzz/corpus/receipt_log_replay/single_receipt.bin:1`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/101#discussion_r3144094558)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Seed corpus with valid `ChioReceipt` payloads** The new `receipt_log_replay` corpus entries are not deserializabl...

### PR #102 -- `chore(mutants): seed cargo-mutants 25.x config + per-crate configs + runbook [M02.P2.T1]`

- **`.cargo/mutants.toml:52`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/102#discussion_r3144127594)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Wire per-crate mutants configs into cargo-mutants** These workspace-wide `examine_globs` rely on per-crate `mutan...

- **`crates/chio-kernel-core/mutants.toml:42`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/102#discussion_r3144132735)  
  > ### Per-crate `mutants.toml` files are never loaded **Medium Severity** <!-- DESCRIPTION START --> `cargo-mutants` 25.x only reads its config from `.cargo/mutants.toml` at the source tree root and doe...

- **`crates/chio-credentials/mutants.toml:41`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/102#discussion_r3144132736)  
  > ### Mutation config lists `include!`d files cargo-mutants ignores **High Severity** <!-- DESCRIPTION START --> `cargo-mutants` discovers source files by following `mod` declarations and does not expan...

### PR #103 -- `ci(mutants): add mutants.yml workflow + helper scripts + releases.toml [M02.P2.T2]`

- **`.github/workflows/mutants.yml:84`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/103#discussion_r3144137926)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Disable job-level continue-on-error before gate flip** With `continue-on-error: true` on the `mutants-pr` job, a...

- **`.github/workflows/mutants.yml:160`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/103#discussion_r3144146511)  
  > ### `--in-diff` receives git ref instead of diff file **High Severity** <!-- DESCRIPTION START --> The `mutants-pr` job passes a Git reference (`origin/${BASE_REF}`) to `cargo mutants --in-diff`. This...

- **`.github/workflows/mutants.yml:38`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/103#discussion_r3144146515)  
  > ### Job-level `continue-on-error` defeats blocking-gate auto-flip **Medium Severity** <!-- DESCRIPTION START --> The header comment claims "the gate flip from advisory to blocking is driven entirely b...

### PR #104 -- `test(fuzz): canonical-JSON structure-aware mutator + 3 targets [M02.P2.T6]`

- **`fuzz/mutators/canonical_json.rs:109`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/104#discussion_r3144159770)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Preserve valid JSON when output exceeds max_size** If the mutated serialization is larger than `max_size`, this p...

- **`fuzz/fuzz_targets/manifest_roundtrip.rs:59`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/104#discussion_r3144159771)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Assert byte-level roundtrip stability in manifest target** The target is documented as a canonical-byte roundtrip...

- **`fuzz/mutators/canonical_json.rs:193`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/104#discussion_r3144167021)  
  > ### Swap indices always equal for common array lengths **Medium Severity** <!-- DESCRIPTION START --> The `swap_array_elements` mutation often results in a no-op. The calculation for index `j` widens...

- **`fuzz/mutators/canonical_json.rs:134`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/104#discussion_r3144167024)  
  > ### Seed reuse locks mutations to fixed depths and tables **High Severity** <!-- DESCRIPTION START --> The `seed` value drives both the mutation type (`% 8`) and the target depth (`% 4`), which locks...

### PR #105 -- `test(dudect): scaffold jwt_verify+mac_eq+scope_subset harness [M02.P2.T3]`

- **`crates/chio-kernel-core/tests/dudect/mac_eq.rs:106`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/105#discussion_r3144167550)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Return measured value from dudect closure** `CtRunner::run_one` only `black_box`es the closure return value, but...

- **`docs/fuzzing/continuous.md:254`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/105#discussion_r3144167551)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Use --test target selection for dudect run commands** This command relies on positional `TESTNAME`, but `cargo te...

### PR #106 -- `chore(oss-fuzz): land OSS-Fuzz integration files [M02.P2.T5]`

- **`infra/oss-fuzz/build.sh:41`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/106#discussion_r3144168547)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Copy fuzz binaries from correct target directory** After `cd "$SRC/arc/fuzz"`, `cargo fuzz build` places artifact...

- **`infra/oss-fuzz/build.sh:41`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/106#discussion_r3144176024)  
  > ### Wrong binary output path breaks OSS-Fuzz build **High Severity** <!-- DESCRIPTION START --> The `cp` path `"../target/x86_64-unknown-linux-gnu/release/$target"` is incorrect. The script `cd`s into...

- **`infra/oss-fuzz/project.yaml:12`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/106#discussion_r3144176028)  
  > ### Rust projects only support address sanitizer in OSS-Fuzz **High Severity** <!-- DESCRIPTION START --> The `undefined` sanitizer listed in `project.yaml` is not supported for Rust projects in OSS-F...

### PR #107 -- `ci(dudect): add nightly workflow + threshold check (two-consecutive-run rule t<4.5) [M02.P2.T4]`

- **`scripts/check-dudect-threshold.sh:93`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/107#discussion_r3144173070)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Compare threshold using full-precision max t** `extract_max_abs_t` emits `max_t` with `"%.4f"` and `verdict` comp...

- **`scripts/check-dudect-threshold.sh:195`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/107#discussion_r3144173073)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Validate --threshold is numeric before using it** The `--threshold` argument is accepted without numeric validati...

- **`.github/workflows/dudect.yml:239`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/107#discussion_r3144182112)  
  > ### Prior run query missing status filter silently breaks correlation **Medium Severity** <!-- DESCRIPTION START --> The `correlate` job's `gh run list` command, intended to find the most recent *comp...

### PR #108 -- `ci(mutants): nightly mutants-fuzz-cocoverage workflow [M02.P2.T7] (closes M02 P2)`

- **`scripts/mutants-fuzz-cocoverage.sh:273`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/108#discussion_r3144171683)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Replay each surviving mutant, not only clean tree** The replay command runs `cargo +nightly fuzz run` directly in...

- **`scripts/mutants-fuzz-cocoverage.sh:254`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/108#discussion_r3144171685)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Remove target-level deduplication of survivor replays** This deduplicates by `target_name`, so only the first sur...

- **`scripts/mutants-fuzz-cocoverage.sh:285`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/108#discussion_r3144180213)  
  > ### jq query extracts object instead of path string **Medium Severity** <!-- DESCRIPTION START --> The jq expression extracts `.scenario.mutant.source_file` but the cargo-mutants JSON schema has `sour...

- **`scripts/mutants-fuzz-cocoverage.sh:291`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/108#discussion_r3144180215)  
  > ### Non-jq fallback never matches MissedMutant summary value **Medium Severity** <!-- DESCRIPTION START --> The non-jq fallback checks for the literal JSON substring `"Missed"` (with closing quote aft...

- **`scripts/mutants-fuzz-cocoverage.sh:284`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/108#discussion_r3144180217)  
  > ### Corpus replayed against clean binary, not mutated **Medium Severity** <!-- DESCRIPTION START --> The `cargo +nightly fuzz run` command runs against the current clean checkout, not against any muta...

### PR #109 -- `fix(release-cpp): dedup vcpkg versions index on retag`

- **`.github/workflows/release-cpp.yml:310`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/109#discussion_r3144314472)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Remove all duplicate tuples when deduplicating versions** This logic only finds a single matching row via `next(....

### PR #110 -- `chore(fuzz): add promote_fuzz_seed.sh + owners.toml [M02.P4.T2]`

- **`scripts/promote_fuzz_seed.sh:203`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/110#discussion_r3144318212)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Invoke fuzz entrypoint in generated libfuzzer test** The generated `libfuzzer` regression test does not execute a...

- **`scripts/promote_fuzz_seed.sh:226`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/110#discussion_r3144318215)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Seed generated proptest with the promoted corpus input** The generated `proptest` body never uses the promoted se...

- **`scripts/promote_fuzz_seed.sh:230`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/110#discussion_r3144325275)  
  > ### Generated proptest test will not compile in most owner crates **Medium Severity** <!-- DESCRIPTION START --> The proptest skeleton emits `use proptest::prelude::*;` and a `proptest!` macro invocat...

- **`scripts/promote_fuzz_seed.sh:208`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/110#discussion_r3144325277)  
  > ### Test filename uses only sha8 and silently overwrites siblings **Low Severity** <!-- DESCRIPTION START --> The output file is named `regression_${SHA8}.rs` / `property_${SHA8}.rs` using only the 32...

- **`scripts/promote_fuzz_seed.sh:245`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/110#discussion_r3144325279)  
  > ### Re-promoting a corpus seed deletes the seed **Medium Severity** <!-- DESCRIPTION START --> When `--input` already points at the destination corpus path (a natural workflow for regenerating a regre...

### PR #111 -- `ci(fuzz): add fuzz_crash_triage.yml workflow + issue template [M02.P4.T1]`

- **`.github/workflows/fuzz_crash_triage.yml:97`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/111#discussion_r3144325203)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Distinguish download failures from empty artifact runs** Treating any `gh run download` non-zero exit as `no-arti...

- **`.github/workflows/fuzz_crash_triage.yml:144`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/111#discussion_r3144325626)  
  > ### cflite_pr crashes likely skipped by target inference **Medium Severity** <!-- DESCRIPTION START --> The target-inference loop infers the fuzz target via substring match on the parent directory's `...

- **`.github/workflows/fuzz_crash_triage.yml:197`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/111#discussion_r3144325628)  
  > ### SHA prefix dedupe search likely never matches **Medium Severity** <!-- DESCRIPTION START --> Dedupe issues a `gh issue list --search "${sha_prefix} in:body"` where `sha_prefix` is the first 16 hex...

### PR #112 -- `ci(fuzz): regression-test deletion guard + ci.yml wiring [M02.P4.T3]`

- **`scripts/check-regression-tests.sh:157`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/112#discussion_r3144325294)  
  > ### Pairing check ignores per-file context, approves all deletions **High Severity** <!-- DESCRIPTION START --> The `grep` on line 151 checks `$SEARCH_TEXT` against `$PAIR_REGEX`, but neither variable...

- **`scripts/check-regression-tests.sh:111`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/112#discussion_r3144325897)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Derive push-event diff base from previous commit** This default base selection makes the guard ineffective on `pu...

- **`scripts/check-regression-tests.sh:151`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/112#discussion_r3144325899)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Require distinct pairing evidence for each deleted test** The per-file loop does not actually pair links to indiv...

### PR #113 -- `ci(fuzz): stand up ClusterFuzzLite bridge [M02.P4.T6]`

- **`.github/workflows/cflite_pr.yml:149`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/113#discussion_r3144326024)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Run fuzzers when .clusterfuzzlite files change** This skip condition turns `.clusterfuzzlite/**`-only PRs into a...

- **`.github/workflows/cflite_pr.yml:95`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/113#discussion_r3144326028)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Trigger fuzz-full mode on label events** The new label gate reads `pull_request.labels` at runtime, but this work...

- **`.clusterfuzzlite/project.yaml:27`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/113#discussion_r3144332156)  
  > ### `storage-repo` placed in wrong file, corpus persistence broken **Medium Severity** <!-- DESCRIPTION START --> The `storage-repo` field is declared in `.clusterfuzzlite/project.yaml`, but ClusterFu...

- **`.github/workflows/cflite_pr.yml:112`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/113#discussion_r3144332157)  
  > ### Unused `cflite_mode` output is dead code **Low Severity** <!-- DESCRIPTION START --> The "Detect fuzz-full label" step writes `cflite_mode=batch` or `cflite_mode=code-change` to `GITHUB_OUTPUT`, b...

### PR #114 -- `docs(fuzzing): author triage.md runbook [M02.P4.T5]`

- **`docs/fuzzing/triage.md:7`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/114#discussion_r3144325691)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Correct crash-to-issue automation prerequisite** This paragraph states that `.github/workflows/fuzz_crash_triage....

- **`docs/fuzzing/triage.md:147`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/114#discussion_r3144325692)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Align High-severity SLO with the referenced source of truth** The runbook says it is documenting the OSS-Fuzz com...

- **`docs/fuzzing/triage.md:222`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/114#discussion_r3144325693)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Remove false assurance about regression-deletion CI enforcement** This section claims `scripts/check-regression-t...

### PR #117 -- `ci(fuzz): add upstream_skips.toml + sunset gate (90d max) [M02.P4.T8]`

- **`scripts/check-upstream-skips.sh:169`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/117#discussion_r3144336375)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Reject unknown TOML content instead of passing empty** The awk parser only handles `[[skips]]` blocks and `skips...

- **`scripts/check-upstream-skips.sh:207`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/117#discussion_r3144336377)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Return parse-error exit code for malformed skip entries** When a `[[skips]]` entry is missing required fields, th...

- **`scripts/check-upstream-skips.sh:178`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/117#discussion_r3144340128)  
  > ### Comment stripping corrupts values containing `#` characters **Medium Severity** <!-- DESCRIPTION START --> The awk inline-comment stripping `sub(/[[:space:]]*#.*$/, "", val)` runs on the raw value...

- **`scripts/check-upstream-skips.sh:236`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/117#discussion_r3144340129)  
  > ### Parse errors exit 1 instead of documented exit 2 **Low Severity** <!-- DESCRIPTION START --> The documented exit code contract specifies exit 2 for "unparseable TOML" (e.g., a `[[skips]]` entry mi...

### PR #118 -- `feat(conformance): make crate publishable with included peer fixtures [M01.P4.T1]`

- **`crates/chio-conformance/Cargo.toml:19`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/118#discussion_r3144371246)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Fix include globs to package bundled conformance fixtures** Change the `include` patterns so they point to files...

- **`crates/chio-conformance/Cargo.toml:20`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/118#discussion_r3144373073)  
  > ### Published crate omits fixtures needed by default options **Medium Severity** <!-- DESCRIPTION START --> The `include` list bundles `scenarios/**`, `peers/python/**`, and `peers/js/**`, but omits `...

### PR #119 -- `feat(replay): implement --bless gate logic with seven-clause fail-closed checks [M04.P2.T1]`

- **`tests/replay/src/bless.rs:227`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/119#discussion_r3144386351)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Reject non-false CI values in bless gate** Clause 6 is documented as "CI env var is unset or false," but this che...

- **`tests/replay/src/bless.rs:434`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/119#discussion_r3144386354)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Restrict arrow-splitting to rename/copy status lines** `dirty_paths()` treats any path containing `" -> "` as a r...

- **`tests/replay/src/bless.rs:229`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/119#discussion_r3144395682)  
  > ### CI check is fail-open instead of fail-closed **Low Severity** <!-- DESCRIPTION START --> The clause 6 CI check only refuses when `CI` equals `"true"` (case-insensitive), but the spec states that `...

- **`tests/replay/src/bless.rs:437`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/119#discussion_r3144395683)  
  > ### Porcelain parser splits non-rename entries containing arrow text **Low Severity** <!-- DESCRIPTION START --> `split_once(" -> ")` is applied to every `git status --porcelain` line, not just rename...

### PR #120 -- `feat(replay): add chio-replay-gate.yml workflow (Linux required-on-main) [M04.P2.T2]`

- **`.github/workflows/chio-replay-gate.yml:113`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/120#discussion_r3144392963)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Distinguish missing test target from build failures** The skip logic in this `if` treats any non-zero exit from `...

- **`.github/workflows/chio-replay-gate.yml:113`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/120#discussion_r3144394586)  
  > ### Silent gate bypass when golden test has compilation errors **Medium Severity** <!-- DESCRIPTION START --> The `--no-run` probe with `2>/dev/null` cannot distinguish between "test target file doesn...

### PR #121 -- `feat(replay): add scripts/bless-replay-goldens.sh wrapper with dirty-tree refusal [M04.P2.T4]`

- **`scripts/bless-replay-goldens.sh:150`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/121#discussion_r3144403030)  
  > ### Initial OUTSIDE_DIRTY already excludes SOURCE_PATTERN, making re-computation dead code **Medium Severity** <!-- DESCRIPTION START --> The initial `OUTSIDE_DIRTY` check on line 150 unconditionally...

- **`scripts/bless-replay-goldens.sh:150`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/121#discussion_r3144403031)  
  > ### Rename destinations bypass the outside-allowlist dirty check **Low Severity** <!-- DESCRIPTION START --> The `OUTSIDE_DIRTY` check uses `awk '{print $1}'`, which only captures the *old* path for r...

### PR #122 -- `feat(cli): add chio conformance run subcommand with peer/scenario/report flags [M01.P4.T2]`

- **`crates/chio-cli/src/cli/conformance.rs:24`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/122#discussion_r3144410144)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Validate --report before running harness** The command starts `run_conformance_harness` before validating `--repo...

- **`crates/chio-cli/src/cli/conformance.rs:35`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/122#discussion_r3144411118)  
  > ### Report flag validated after expensive harness execution **Medium Severity** <!-- DESCRIPTION START --> The `--report` flag value is validated only *after* `run_conformance_harness` completes. That...

### PR #123 -- `feat(replay): add macOS smoke + seed-immutable guard to chio-replay-gate workflow [M04.P2.T3]`

- **`.github/workflows/chio-replay-gate.yml:120`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/123#discussion_r3144416593)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Fail on golden test compile errors instead of skipping** The `if cargo test ... --test golden_byte_equivalence --...

- **`.github/workflows/chio-replay-gate.yml:223`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/123#discussion_r3144599815)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Verify seed digest against protected reference** The guard computes `expected` from `tests/replay/test-key.seed.s...

### PR #124 -- `test(conformance): add cpp_peer_p0.rs covering mcp_core and auth via chio-cpp-kernel-ffi [M01.P4.T6]`

- **`crates/chio-conformance/Cargo.toml:19`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/124#discussion_r3144428882)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Package conformance assets from the crate directory** These `include` globs point to `tests/conformance/...` rela...

- **`crates/chio-conformance/Cargo.toml:20`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/124#discussion_r3144437661)  
  > ### Cargo `include` paths resolve to nonexistent crate-relative directories **Medium Severity** <!-- DESCRIPTION START --> The `include` patterns for conformance scenarios and peers in `Cargo.toml` ar...

- **`crates/chio-conformance/Cargo.toml:50`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/124#discussion_r3144437663)  
  > ### Feature flag `in-repo-fixtures` declared but never consumed **Low Severity** <!-- DESCRIPTION START --> The `in-repo-fixtures` feature is declared and documented as controlling path resolution beh...

### PR #126 -- `feat(replay): bless 50 corpus goldens and add docs/replay-compat.md bootstrap [M04.P2.T5]`

- **`.github/workflows/chio-replay-gate.yml:120`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/126#discussion_r3144478562)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Fail gate when golden test build errors** This step treats any non-zero exit from `cargo test --test golden_byte_...

- **`tests/replay/src/bless.rs:227`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/126#discussion_r3144478563)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Reject non-false CI values in bless gate** Clause 6 is documented as “CI env var is unset or false,” but the impl...

- **`tests/replay/src/bless.rs:434`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/126#discussion_r3144478564)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Check both rename paths in dirty-tree allowlist** For porcelain rename entries (`old -> new`), the parser keeps o...

- **`tests/replay/tests/golden_byte_equivalence.rs:181`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/126#discussion_r3144480489)  
  > ### Silent fallback to "unknown" masks malformed fixture manifests **Low Severity** <!-- DESCRIPTION START --> The `expected_verdict` and `clock` fields are extracted with `.unwrap_or("unknown")`, sil...

### PR #127 -- `feat(conformance): add fetch-peers subcommand and peers.lock.toml [M01.P4.T4]`

- **`crates/chio-cli/src/cli/conformance.rs:195`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/127#discussion_r3144483759)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Resolve lockfile path at runtime instead of build path** `default_peers_lock_path()` bakes `env!("CARGO_MANIFEST_...

- **`crates/chio-conformance/src/peers.rs:186`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/127#discussion_r3144489551)  
  > ### Redundant `sha256_hex` duplicates existing `chio_core` function **Low Severity** <!-- DESCRIPTION START --> The new `sha256_hex` function in `peers.rs` duplicates `chio_core::sha256_hex`, which is...

- **`crates/chio-cli/src/cli/conformance.rs:323`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/127#discussion_r3144489552)  
  > ### Unreachable fallback leaves empty filename unhandled **Low Severity** <!-- DESCRIPTION START --> The `unwrap_or("peer.bin")` fallback is unreachable because `rsplit('/').next()` on a non-empty str...

- **`crates/chio-cli/src/cli/conformance.rs:323`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/127#discussion_r3144605570)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Extract fetched artifacts before writing peer output** This download path persists the raw response bytes under a...

- **`crates/chio-cli/src/cli/conformance.rs:276`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/127#discussion_r3144605571)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Add explicit timeout to peer download client** The blocking HTTP client is built with default settings and no tim...

### PR #128 -- `chore(codeowners): lock tests/replay/goldens and test-key.seed paths to M04 [M04.P2.T6]`

- **`.github/workflows/chio-replay-gate.yml:120`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/128#discussion_r3144484654)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Fail the gate when golden test compile probe errors** This probe treats any non-zero exit from `cargo test ... --...

- **`tests/replay/tests/golden_byte_equivalence.rs:206`** by cursor (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/128#discussion_r3144490367)  
  > ### Root hash skips canonicalization, fragile to feature unification **Medium Severity** <!-- DESCRIPTION START --> The root hash is computed from `serde_json::to_vec` of raw `json!` values whose keys...

### PR #129 -- `feat(replay): add release_compat_matrix.toml with v0.1.0 and v2.0 entries [M04.P3.T1]`

- **`.github/workflows/chio-replay-gate.yml:120`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/129#discussion_r3144490739)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Fail when golden test compile fails instead of skipping** In `.github/workflows/chio-replay-gate.yml`, the `if ca...

- **`tests/replay/src/bless.rs:227`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/129#discussion_r3144490741)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Refuse bless whenever CI is set to non-false values** Clause 6 says bless is allowed only when `CI` is unset or `...

### PR #130 -- `docs(conformance): land standalone external-consumer flow guide [M01.P4.T5]`

- **`crates/chio-cli/src/cli/conformance.rs:195`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/130#discussion_r3144502361)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Load peers lockfile from shipped runtime assets** `default_peers_lock_path()` hardcodes a compile-time source-tre...

- **`crates/chio-cli/src/cli/conformance.rs:30`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/130#discussion_r3144502367)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Validate --report before starting conformance execution** The command runs `run_conformance_harness` before valid...

- **`docs/conformance.md:61`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/130#discussion_r3144502373)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Correct install docs to avoid missing `chio` command** The guide states that `cargo install chio-conformance` ins...

- **`docs/conformance.md:35`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/130#discussion_r3144608364)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Remove toolchain-free guarantee from fetch-peers flow** This guide promises that users can run conformance with n...

- **`docs/conformance.md:146`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/130#discussion_r3144608367)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Clarify that default run covers only mcp_core scenarios** The text says `chio conformance run --peer python` runs...

- **`docs/conformance.md:186`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/130#discussion_r3144608369)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Replace invalid --scenario example with real scenario ID** The example uses `--scenario tasks_long_running`, but...

### PR #131 -- `test(cli): add conformance_cli insta-snapshot test for report shape stability [M01.P4.T3]`

- **`crates/chio-cli/src/cli/conformance.rs:195`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/131#discussion_r3144507506)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Resolve peers lockfile from runtime-accessible location** `default_peers_lock_path()` bakes in `env!("CARGO_MANIF...

- **`crates/chio-cli/src/cli/conformance.rs:37`** by cursor (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/131#discussion_r3144510961)  
  > ### Report format validated after expensive harness execution **Medium Severity** <!-- DESCRIPTION START --> `cmd_conformance_run` calls `run_conformance_harness` (which spawns servers, builds executa...

- **`crates/chio-conformance/src/peers.rs:186`** by cursor (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/131#discussion_r3144510963)  
  > ### Duplicate `sha256_hex` when dependency already exports it **Low Severity** <!-- DESCRIPTION START --> `sha256_hex` in `peers.rs` reimplements a function already exported by `chio-core-types` as `c...

- **`crates/chio-cli/tests/conformance_cli.rs:99`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/131#discussion_r3144510965)  
  > ### Test unnecessarily requires Node.js for Python-only run **Medium Severity** <!-- DESCRIPTION START --> `conformance_run_python_report_shape_is_stable` gates on `command_available("node")`, but the...

- **`crates/chio-cli/tests/conformance_cli.rs:98`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/131#discussion_r3144608150)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Remove unnecessary Node.js gate for python conformance test** The live snapshot test returns early when `node` is...

### PR #132 -- `feat(ci): extend spec-drift.yml with vectors-byte-stable, schema-coverage, cross-lang-bytes jobs [M01.P5.T3]`

- **`.github/workflows/spec-drift.yml:184`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/132#discussion_r3144520795)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Detect untracked files in vectors-byte-stable check** `git diff --exit-code tests/bindings/vectors` only reports...

### PR #133 -- `feat(replay): add strict TOML matrix loader for release_compat_matrix.toml [M04.P3.T2]`

- **`.github/workflows/chio-replay-gate.yml:120`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/133#discussion_r3144523451)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Fail on golden test build errors instead of skipping** This `if cargo test ... --no-run` guard treats every non-z...

- **`tests/replay/src/cross_version.rs:171`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/133#discussion_r3144523453)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Validate `supported_until` tags in matrix entries** `CompatEntry::validate` checks `tag`, `bundle_sha256`, `bundl...

- **`tests/replay/src/cross_version.rs:151`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/133#discussion_r3144610845)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Reject duplicate tag entries during matrix validation** `CompatMatrix::validate` only validates each row independ...

### PR #134 -- `feat(ci): add conformance-matrix.yml + vectors-staleness.yml nightly workflows [M01.P5.T4]`

- **`crates/chio-cli/src/cli/conformance.rs:195`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/134#discussion_r3144531441)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Resolve peers.lock path from installed artifact, not source tree** `default_peers_lock_path()` hardcodes `env!("C...

- **`crates/chio-conformance/Cargo.toml:20`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/134#discussion_r3144531444)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Include mcp_core fixture files in published crate payload** The publish `include` list ships scenarios and peer d...

- **`crates/chio-conformance/peers.lock.toml:31`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/134#discussion_r3144531446)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Replace placeholder peer SHA256 pins before enabling fetch** This lock entry (and the rest of the file) uses plac...

- **`crates/chio-cli/src/cli/conformance.rs:37`** by cursor (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/134#discussion_r3144558957)  
  > ### Report format validated after expensive harness execution **Medium Severity** <!-- DESCRIPTION START --> The `--report` format validation (lines 30-37) happens *after* `run_conformance_harness` (l...

- **`.github/workflows/conformance-matrix.yml:120`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/134#discussion_r3144558960)  
  > ### Placeholder lockfile causes guaranteed nightly workflow failure **Medium Severity** <!-- DESCRIPTION START --> The `Fetch python peer adapter binary` step runs `chio conformance fetch-peers --lang...

### PR #135 -- `docs(replay): document last-N=5 ratchet rule and v3.0 strict floor [M04.P3.T6]`

- **`.github/workflows/chio-replay-gate.yml:223`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/135#discussion_r3144538288)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Enforce seed immutability against a trusted baseline** The `seed-immutable` job currently verifies `test-key.seed...

- **`.github/workflows/chio-replay-gate.yml:117`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/135#discussion_r3144538289)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Fail CI on golden test compile errors instead of skipping** This conditional treats any non-zero exit from `cargo...

- **`tests/replay/src/bless.rs:227`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/135#discussion_r3144538290)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Reject CI values other than explicit false** Clause 6 is documented as “CI env var is unset or false”, but this c...

### PR #136 -- `feat(ci): add advisory schema-breaking-change PR bot using json-schema-diff [M01.P5.T5]`

- **`.github/workflows/schema-breaking-change.yml:82`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/136#discussion_r3144545923)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Use git glob pathspec when listing changed schemas** The changed-file query uses `git diff ... -- 'spec/schemas/*...

- **`.github/workflows/schema-breaking-change.yml:136`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/136#discussion_r3144545928)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Update sticky comment when breakages are fixed** The comment step is gated to run only when `breaking_count` is n...

- **`.github/workflows/schema-breaking-change.yml:132`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/136#discussion_r3144557050)  
  > ### Static heredoc delimiter risks output truncation or injection **Low Severity** <!-- DESCRIPTION START --> The multiline `summary` output uses a fixed heredoc delimiter `CHIO_DIFF_EOF`. If the `sum...

- **`.github/workflows/schema-breaking-change.yml:81`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/136#discussion_r3144608545)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Diff changed schemas from merge base, not base tip** Using `git diff "${BASE_SHA}" "${HEAD_SHA}"` compares the tw...

- **`.github/workflows/schema-breaking-change.yml:103`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/136#discussion_r3144608547)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Resolve renamed schemas from their source path** Renames are included by `--diff-filter=AMR`, but `--name-only` y...

- **`.github/workflows/schema-breaking-change.yml:125`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/136#discussion_r3144609835)  
  > ### Missing newline between snippets corrupts multi-file markdown output **Medium Severity** <!-- DESCRIPTION START --> When multiple schemas have breaking changes, the PR comment markdown is corrupte...

- **`.github/workflows/schema-breaking-change.yml:41`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/136#discussion_r3144609838)  
  > ### Unnecessary Cargo environment variable in Node.js workflow **Low Severity** <!-- DESCRIPTION START --> `CARGO_TERM_COLOR: always` is a Rust/Cargo environment variable, but this workflow only uses...

- **`.github/workflows/schema-breaking-change.yml:136`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/136#discussion_r3144609842)  
  > ### Stale breaking-change comment persists after regression is fixed **Medium Severity** <!-- DESCRIPTION START --> When a subsequent push resolves all breaking changes, `breaking_count` becomes `0` a...

- **`.github/workflows/schema-breaking-change.yml:81`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/136#discussion_r3144609847)  
  > ### Renamed schema files silently skip breaking-change detection **Medium Severity** <!-- DESCRIPTION START --> The `--diff-filter=AMR` includes `R` (renamed) files, but `git diff --name-only` emits o...

### PR #137 -- `test(differential): add receipt_encoding_diff cross-language byte-equivalence test [M01.P5.T2]`

- **`formal/diff-tests/tests/receipt_encoding_diff.rs:538`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/137#discussion_r3144554383)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Fail live TS differential on subprocess errors** When `CHIO_LIVE_SDK_DIFFERENTIAL=1` is set and Node is available...

- **`formal/diff-tests/tests/receipt_encoding_diff.rs:539`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/137#discussion_r3144560922)  
  > ### TS live test silently skips on genuine encoder failures **Medium Severity** <!-- DESCRIPTION START --> The `live_ts_encoder_matches_rust` test skips on any non-zero Node exit code, unlike the Pyth...

### PR #138 -- `feat(replay): add bundle fetch + sha256-pinned cache for cross-version harness [M04.P3.T3]`

- **`.github/workflows/chio-replay-gate.yml:120`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/138#discussion_r3144557610)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Fail CI when golden test probe returns non-missing errors** The `if cargo test ... --no-run --quiet` probe treats...

- **`tests/replay/src/bless.rs:227`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/138#discussion_r3144557611)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Reject all CI truthy values in bless gate** Clause 6 is documented as allowing bless only when `CI` is unset or `...

- **`tests/replay/tests/golden_byte_equivalence.rs:181`** by cursor (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/138#discussion_r3144563039)  
  > ### Silent default masks missing manifest fields **Low Severity** <!-- DESCRIPTION START --> The `expected_verdict` and `clock` fields are read with `unwrap_or("unknown")`, silently substituting a pla...

### PR #139 -- `feat(replay): implement cross_version_replay re-verify against current kernel [M04.P3.T4]`

- **`.github/workflows/chio-replay-gate.yml:120`** by chatgpt-codex-connector (outdated)  
  [thread](https://github.com/bb-connor/arc/pull/139#discussion_r3144584105)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Run golden byte-equivalence failures instead of skipping** The guard command in this step treats any non-zero exi...

- **`tests/replay/tests/cross_version_replay.rs:112`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/139#discussion_r3144584109)  
  > **<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)</sub></sub> Reject supported bundles with unsigned receipts** Supported entries currently fail only on root mismatch or expli...

### PR #140 -- `feat(replay): add release-tagged.yml auto-append + cross-version replay-gate job [M04.P3.T5]`

- **`.github/workflows/release-tagged.yml:52`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/140#discussion_r3144588619)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Derive `released_at` from release payload, not runner clock** `released_at` is computed with `date -u` at workflo...

- **`.github/workflows/release-tagged.yml:84`** by chatgpt-codex-connector (current)  
  [thread](https://github.com/bb-connor/arc/pull/140#discussion_r3144588622)  
  > **<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub> Skip append when tag already exists in compatibility matrix** This step unconditionally appends a new `[[entry]]`...

- **`.github/workflows/release-tagged.yml:51`** by cursor (current)  
  [thread](https://github.com/bb-connor/arc/pull/140#discussion_r3144591446)  
  > ### Script injection via unsanitized release tag name **High Severity** <!-- DESCRIPTION START --> `github.event.release.tag_name` is interpolated directly into `run:` shell blocks via `${{ }}` expres...
