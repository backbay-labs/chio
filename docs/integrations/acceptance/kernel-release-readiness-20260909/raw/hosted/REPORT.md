# Hosted release audit

Source: d8c5f53705173e614a853bad6c0a85acfdf1212b, clean worktree /Users/connor/Medica/backbay/standalone/arc/.worktrees/kernel-release-audit-20260909.
Read-only inspection only. No push, dispatch, settings change, source edit, build, or publication.

## Exact candidate evidence

Both bb-connor/arc and backbay-labs/chio commit and check-run API queries return HTTP 422, No commit found for this SHA. Both actions/runs?head_sha=<candidate> queries return total_count 0. The selected local debug artifact has no hosted exact-candidate qualification, binary build, or provenance evidence and is not a public release.

Arc Actions are enabled. Chio Actions are disabled. Arc main is f5566d9a765c21cb36652a99c79de64968a656bf; Chio main is 5b8bec41d32f3838b880576fe6123c983ecebf8d. The Arc compare endpoint reports Arc main two commits ahead, zero behind. A mirror exists at an older point, not at the candidate.

## Historical hosted identifiers

- Arc latest Release Qualification: run 33717023364, attempt 1, head f5566d9a765c21cb36652a99c79de64968a656bf, failure. Job 100528254571 failed Release qualification (step25), Retain formal proof evidence(step26), and Stage hosted web3 qualification artifacts(step29). This historical failure is not the candidate's failure.
- Arc qualification success-filter query returns total_count0. This is observed API history, not a claim about deleted runs.
- Arc latest Release Binaries: 25357982343, failure. The returned history contains four runs; only 24805546785 succeeded, for 0567923f7a82d662e32036f53b3fa710919a7cf9 on 2026-04-22.
- Arc SLSA history contains three skipped runs: 25368001296,25362701819,25245382882. No successful provenance run returned.
- Chio qualification/binaries/SLSA histories each return total_count0.

## Mirror identity

Both v0.1.0 refs identify annotated tag object 6d741458cf57877ba8639b8b7cfc5342fd47f97b, which points to commit 0567923f7a82d662e32036f53b3fa710919a7cf9.
Arc release312477062 was published 2026-04-22T22:47:39Z; Chio release385525769 was published 2026-09-09T13:18:48Z. All11 asset names on Chio have identical GitHub-reported SHA256 digests to Arc: five archives, five individual checksum files, SHA256SUMS. Arc additionally has chio.rb; Chio does not. Neither listed release has .sig/.pem/.intoto.jsonl assets. Archive bytes were not redownloaded in this audit, so equality here is API-digest evidence.

Copying identical Git objects preserves commit and tag identity. Copying identical release assets preserves their bytes; it does not create a new build, move repository-bound check runs, change the signing identity, or qualify newer source. Verification must retain original source/workflow identity or use a newly qualified destination build; it must not relabel an Arc attestation as Chio evidence.

## Source workflow prerequisites and limitations

- release-qualification.yml:3-6 runs on main push or workflow_dispatch. At:70-212 installs Rust/MSRV1.94.1, cargo-vet0.10.2, Java21/Apalache, Lean, Node22/Bun1.3.3, Python3.12, Go1.23.0, pinned Aeneas/Charon, Creusot and Kani, portable targets/tools, and Linux bubblewrap support. PostgreSQL16.6 is provisioned at:27-47. SDK parity and dashboard preparation precede qualify-release.sh at:214-228. Web3 qualification and MSRV workspace lanes follow at:241-252. Artifact release-qualification is retained21days at:254-261.
- qualify-release.sh:33-40 requires a clean exact candidate and matches GITHUB_SHA if present. It invokes ci-workspace at:44, exact-candidate cognition-market qualification:62-63, required formal fleet gates:65-89, providers/trust-control/browser/mobile/SDK lanes:90-116, conformance/repeated cluster/coverage65%:292-299, and candidate-bound manifest generation AND verification:301-314.
- ci-workspace.sh:6-56 includes release-input, architecture/formal/Aeneas/Creusot/Kani/no-bypass/portable/strict proof gates, formatting, clippy, workspace build, and workspace tests (WASM library separated).
- release-binaries.yml:7-16 accepts v*.*.* tag push or dispatch. Dispatch must originate from the matching tag; checkout uses immutable github.sha and rechecks tag target at:69-116. Five platform targets build cargo auditable --release --locked (:152-198), produce SBOMs and checksums, sign archives with OIDC/cosign (:389-455), and store exact tag/ref/SHA/run metadata (:370-386).
- Publication job needs ONLY build (:477-482), with draft:false (:683-701). It does not check Release Qualification, Security contract, or SLSA first. Consequently successful publication is not itself full qualification. The dispatch description mentioning a draft is misleading relative to actual draft:false.
- slsa.yml:30-45 is a separate successful-Release-Binaries workflow_run listener. It validates consistent matrix metadata, exact workflow_run.head_sha, and tag-shaped source ref (:58-111), then attaches chio-<source_sha>.intoto.jsonl using the pinned reusable generator (:113-130). Its own name/docs claim SLSA L2; release-binaries.yml:3-5 says L3. Avoid an unsupported L3 claim.
- Cargo.toml:206 still says workspace version0.1.0, including chio-cli. New local behavior must not be identified solely by --version; a coherent new release identity is required before shipping it as a later public artifact.

## Current hosted security enforcement

Arc active ruleset22033486, main-required-checks, requires Build, lint, test; MSRV build and test; cargo-vet (locked supply-chain audit); cargo-deny (supply-chain bans/advisories/licenses). No bypass actors; current_user_can_bypass=never. Chio rulesets query returns an empty list. Do not infer branch protection absence beyond that endpoint.

Security-contract machinery is separate: enterprise-hardening.yml takes exact source_repository/source_sha (:4-23), checks authorized source/evidence pins (:699-719), and validates pinned verifier/public signer/canonical policy (:757-774). Finalizer requires authenticated capture/merge/source identities and dedicated App ID/install/private key (enterprise-evidence-finalizer.yml:2332-2344). Repository variable/secret name inventories show Arc lacks repository-level CHIO_COMMITTED_LINUX_EVIDENCE_SHA, CHIO_ENTERPRISE_EVIDENCE_POLICY_JSON, CHIO_SECURITY_APP_INSTALLATION_ID, and CHIO_SECURITY_APP_PRIVATE_KEY_PEM. Arc does have authorized-source/security-definition/signer/verifier pins and App ID. Chio has no repository variables or secrets. Organization/environment inherited configuration was not queried, so absence is scoped to repository-level inventory. Current ci.yml does not invoke enterprise-hardening.yml. These workflows are not an automatically satisfied gate for this candidate.

## Concrete resolving work

1. Publish the exact reviewed candidate into the intended source repository through its required CI/security process; preserve SHA identity if mirroring.
2. Run exact-source release qualification and resolve failures. Preserve hosted artifact/run identities; local gates cannot supply GitHub/OIDC provenance.
3. If building on Chio, enable its Actions and install required trusted configuration through authorized operator procedures; if building on Arc, preserve Arc-origin signatures and provenance when mirroring assets.
4. Choose a coherent new version/tag; run all five release builds, inspect signature/SBOM/checksum evidence, finish successful SLSA generation, and verify public installation against that exact artifact. Do not overwrite v0.1.0 or relabel the debug candidate.

## Evidence layout

Each API query has .stdout.json, .stderr.txt, and .meta.json containing command, timestamp, and exit code. Variable/secret inventories intentionally omit values. main-checks is only the first100 of877 results and is not used for any complete-main-status claim. SHA256SUMS.json covers raw query evidence.
