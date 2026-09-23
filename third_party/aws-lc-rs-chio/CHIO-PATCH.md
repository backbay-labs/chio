# Chio AWS-LC Rust DES repair

Source: aws-lc-rs 1.18.1 registry archive, SHA-256
`b281d307588d634de920874890732659e2e7672f72b5e10e81badc1a8a83621e`.

This fork repairs DES and TDEA key validation in the optional `legacy-des`
feature. DES parity bits do not contribute to the effective key, but the
registry release passes arbitrary parity to native weak-key detection and
compares TDEA components byte for byte. That accepts parity variants of known
weak and semi-weak DES keys, and it accepts TDEA components that encode the
same effective key with different parity.

The repair normalizes every DES key to odd parity before calling
`DES_set_key`, rejects every nonzero native result, and compares TDEA
components after masking their parity bits. The regression target covers weak
and semi-weak parity variants and parity-distinct equal TDEA components. It
fails against the registry release and passes against this fork on native
Linux x86_64. The complete default and FIPS library test suites also pass.

Five em dashes in upstream documentation and Rust documentation comments are
normalized to hyphens for the repository text convention. They do not affect
compiled behavior.

Eight upstream test-vector files also have CRLF endings, trailing whitespace
or trailing blank lines normalized for the repository diff check. The test
parser already ignores these differences; vector keys and values are unchanged.

The repository retains the registry archive, source provenance, review notes,
negative result, repaired result, commands, and hashes under
`output/process-security-20260915/resume-20260921/aws-lc/`.

This patch is not a certification of the entire dependency.

```sh
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml \
  --features legacy-des --test des_parity_regression
```
