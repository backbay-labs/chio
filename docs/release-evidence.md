# Release Evidence

This document is the external-reviewer entry point for Chio release evidence.
It is written for the crypto and protocol reviewer and the HITRUST i1 assessor.

## Checksum Index

For release `v<tag>`, fetch:

- GitHub Release assets from `https://github.com/backbay-labs/chio/releases/tag/v<tag>`
- Checksum index from `supply-chain/checksums/v<tag>.txt`
- Checksum index signature from `supply-chain/checksums/v<tag>.txt.sig`
- Checksum index certificate from `supply-chain/checksums/v<tag>.txt.pem`
- SLSA provenance asset `chio-<source_sha>.intoto.jsonl` from the same GitHub Release

The checksum index contains one row per release archive:

```text
<sha256>  <filename>
```

Verify downloaded artifacts with stock checksum tools:

```bash
sha256sum --check v<tag>.txt
```

On macOS without GNU coreutils:

```bash
shasum -a 256 -c v<tag>.txt
```

## Signature Verification

The checksum index is signed by the `release-binaries.yml` workflow using
keyless Sigstore signing. Verify it with:

```bash
cosign verify-blob \
  --certificate v<tag>.txt.pem \
  --signature v<tag>.txt.sig \
  v<tag>.txt
```

Use the certificate identity and issuer printed by `cosign verify-blob` to
confirm the signer is GitHub Actions for `backbay-labs/chio`.

## Rekor Witness

The checksum index header carries the SLSA provenance asset name:

```text
# slsa_provenance chio-<source_sha>.intoto.jsonl
```

After `.github/workflows/slsa.yml` publishes that asset, search
`https://search.sigstore.dev` for the provenance payload or the checksum-index
signature digest. Rekor is the transparency-log witness; the in-repo checksum
index is the stable reviewer index.

## Reproducibility Scope

The release pipeline guarantees Linux x86_64 reproducibility for the `chio`
binary. macOS and Windows release archives are still checksum-published and
signed, but they are not claimed to be byte-reproducible because codesign and
PE timestamp behavior remains platform-dependent.
