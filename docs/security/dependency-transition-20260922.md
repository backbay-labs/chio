# September 22 dependency transition

This change updates the Rust and JavaScript dependency closure used by the
public CLI, SDKs and Docker builds. The source patch and lockfiles are retained
in the public repository so external builds use the same reviewed source.

## Dependency and source identity

| Dependency | Selected version | Reason |
| --- | --- | --- |
| rustls | 0.23.45 | RUSTSEC-2026-0285 repair |
| rustls-webpki | 0.103.15 | Compatible patched certificate verifier |
| der | 0.8.2 | Replace yanked 0.8.0 |
| aws-lc-rs | 1.18.1 plus the documented Chio patch | rustls dependency update with retained DES key validation |
| js-yaml | 4.3.2 | GHSA-2883-xcg3-v3hh repair |
| vitest and @vitest/mocker | 4.1.11 | GHSA-82fw-gwwq-j7x9 repair |
| sharp | 0.35.4 | GHSA-rgj7-g3m4-5g8c repair |
| Metro build tools | 0.84.5 | Remove the vulnerable image-size parser from the mobile build dependency chain |
| Next.js peer and example requirement | >=15.5.24 <16 | GHSA-2xp9-vwfh-vxw4 and GHSA-p293-qw3h-jr36 repairs |

[CHIO-PATCH.md](../../third_party/aws-lc-rs-chio/CHIO-PATCH.md)
identifies the registry archive, local semantic changes and vector whitespace
normalization. Root and generated Docker manifests retain the same source patch;
affected Docker builders copy the vendor directory. Existing audit records cover
the native and Rust updates without a new cargo-vet exemption. The upstream cipher
file has an exact-size, expiring source-hygiene allowance; other file limits remain
enforced.

JavaScript workspace lockfiles retain the public package membership. Express
and Fastify conformance fixtures now answer the existing receipt-verification endpoint with typed receipt
roles, and include rejection cases. The verdict matrix checks all 72 canonical
scenario identifiers. These transport fixtures do not establish cryptographic
acceptance.

## Qualification

The retained DES regression exercises key parity validation against the patched
source. Qualification also covers cargo-vet, cargo-deny, Docker source inputs,
frozen JavaScript resolution and the TypeScript build and conformance commands.
Passing results must identify the public source revision that was checked.

Review the vendor provenance, dependency/audit closure, container inputs, SDK
compatibility and qualification documentation as separate slices. Require terminal
hosted checks and independent review before integration.
