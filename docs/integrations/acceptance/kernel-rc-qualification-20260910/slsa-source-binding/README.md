# Tagged source and pinned builder provenance repair

Confidence: high for the local policy controls and actual upstream cryptographic
compatibility. Chio hosted release acceptance remains unresolved.

The former `workflow_run` listener passed its default-branch GitHub context to
an otherwise tagged archive build. Archive metadata did not correct the signed
config source and materials. The pinned upstream generic generator's default
precompiled mode also requires a SemVer tag. Stock slsa-verifier v2.7.1 requires
that tag even when a caller supplies an explicit builder ID.

The repair invokes the local SLSA workflow from the original Release Binaries
run. It requires five target artifacts whose metadata matches source, tag,
version, target, run and attempt. The upstream workflow remains pinned to
`f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`, uses its supported source compilation
mode, and does not upload release assets itself. Its builder ID comes from the
OIDC job workflow ref. Standard cosign v2.4.1 bundle verification authenticates
artifact bytes, the exact SHA builder certificate identity, GitHub issuer,
source SHA, repository and ref. A separate policy then checks the authenticated
SLSA builder, complete five-subject list, source/material commit, caller workflow,
event, run and attempt. Only a passing bundle can be attached, with no overwrite
or candidate publication. This is a reviewed explicit builder policy, not a
stock-verifier compatibility claim or a transparency/certificate bypass.

## Actual cryptographic observations

The unchanged public signed generic v2.1.0 fixture and corresponding binary from
slsa-verifier v2.7.1 were downloaded and verified using the actual checksum-checked
cosign v2.4.1 executable. Its exact command exited zero with `Verified OK`.
Eight independent real commands exited one for a foreign builder, source SHA,
repository, ref, issuer, changed artifact, changed signature, or changed payload.
The negative control that expects the Chio SHA builder against the real fixture's
SemVer builder correctly fails. No certificate, statement or signer identity was
rewritten to create a positive result. Disposable mutated copies are negatives.

This fixture authenticates upstream example-package source
`4d329c75e7ec1725f7c9ce917a8799d408d06be3`, a main-branch workflow dispatch and
upstream SemVer builder. It establishes supported bundle cryptography only. It
does not pass Chio's tagged-source/SHA-builder policy. Its binary was hashed and
verified as data, never executed.

## Local controls and remaining gate

The retained focused run passes 13 adversarial provenance methods, 13 existing
candidate asset methods, the existing source-gate and binary inventory suites,
release input validation, workflow lint, and whitespace validation. Synthetic
policy/tool fixtures remain labelled as such. The actual crypto commands above
are separate from those synthetic tests.

Required next evidence is a successful Chio tagged Release Binaries run using
the new nested workflow and immutable upstream generator SHA, with all five exact
hosted archives verified against the actual emitted bundle and authenticated
source/builder/caller/run/attempt policy before attachment. Installation and all
six real-host acceptance gates still require their own evidence. No tag, release,
publication, source gate exemption or manual attestation rewrite occurred here.

`manifest.json` records exact tool, raw input and compressed evidence identities.
Raw files are losslessly gzip-compressed with mtime zero; decompressed hashes
match the originals. The retained upstream test fixture remains third-party
material under its [upstream license](https://github.com/slsa-framework/slsa-verifier/blob/v2.7.1/LICENSE).

Primary contracts:

- [GitHub reusable caller context](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#github-context)
- [Pinned upstream generic workflow](https://github.com/slsa-framework/slsa-github-generator/blob/f7dd8c54c2067bafc12ca7a55595d5ee9b75204a/.github/workflows/generator_generic_slsa3.yml)
- [Builder ID from authenticated OIDC job workflow ref](https://github.com/slsa-framework/slsa-github-generator/blob/f7dd8c54c2067bafc12ca7a55595d5ee9b75204a/slsa/provenance.go#L59-L68)
- [Stock verifier's builder-ref policy](https://github.com/slsa-framework/slsa-verifier/blob/v2.7.1/verifiers/internal/gha/builder.go)
- [Cosign standard Sigstore bundle verification](https://github.com/sigstore/cosign/blob/v2.4.1/cmd/cosign/cli/verify/verify_bundle.go)
- [Actual signed fixture and matching binary](https://github.com/slsa-framework/slsa-verifier/tree/v2.7.1/cli/slsa-verifier/testdata/gha_generic/v2.1.0)
