# Chio AWS-LC Rust DES repair

Source: aws-lc-rs 1.18.1 registry archive, SHA-256
`b281d307588d634de920874890732659e2e7672f72b5e10e81badc1a8a83621e`.
The archive is publicly available at
`https://static.crates.io/crates/aws-lc-rs/aws-lc-rs-1.18.1.crate`.
The published crate records upstream commit
`22e629d5c46276497a24ee3e575be4315940e7cb` in
`.cargo_vcs_info.json`.

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

The tracked [CHIO-PATCH.patch](CHIO-PATCH.patch) is the complete change to
files present in the registry archive, excluding this provenance document.
It adds the DES regression target and changes the crate manifest, DES key
validation, and the five text-convention occurrences. The 71 test fixtures
missing from the published archive are copied from the upstream commit above.
Their checked-in hashes are in
[CHIO-RESTORED-FIXTURES.sha256](CHIO-RESTORED-FIXTURES.sha256).
Eight fixtures were normalized with the exact transformation below. All
other fixture bytes match the upstream commit. These fixtures are test data,
not production source.

To independently reconstruct the fork, extract the verified registry archive,
apply `CHIO-PATCH.patch` from the extracted crate root, and copy the fixture
paths named in `CHIO-RESTORED-FIXTURES.sha256` from the upstream commit's
`aws-lc-rs/` directory. Normalize the following eight files with
`perl -0777 -pi -e 's/\r\n/\n/g; s/[ \t]+(?=\n)//g; s/\n+\z/\n/'`:

```text
src/test/test_1_tests.txt
tests/data/cavp_3des_cmac_tests.txt
tests/data/cavp_aes128_cmac_tests.txt
tests/data/cavp_aes192_cmac_tests.txt
tests/data/cavp_aes256_cmac_tests.txt
tests/data/digest_tests.txt
tests/data/rsa_pkcs1_sign_tests.txt
tests/data/rsa_pss_verify_tests.txt
```

Run `sha256sum -c CHIO-RESTORED-FIXTURES.sha256` from the reconstructed
crate root. Then compare every file with this checked-in directory, excluding
`CHIO-PATCH.md`, `CHIO-PATCH.patch`, and
`CHIO-RESTORED-FIXTURES.sha256`, which are review metadata. The regression
was observed to fail against the published crate and pass against this fork
with separate Cargo target directories; the commands below exercise the fork.

This patch is not a certification of the entire dependency.

```sh
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml \
  --features legacy-des --test des_parity_regression
```
