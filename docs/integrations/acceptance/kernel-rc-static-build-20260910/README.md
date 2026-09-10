# Local static kernel candidate, 2026-09-10

The exact local Apple Silicon candidate below completed an optimized
`cargo auditable` build, started with non-system package-manager libraries
denied, and passed the retained embedded Rust inventory validator. Confidence
is high for these observed local results. This record does not establish host
acceptance, a hosted build artifact, signing, provenance, or public delivery.

| Identity | Recorded value |
| --- | --- |
| Kernel source | `bafa02b06de93553cecb6f60b340f3dd8fd9b401` |
| Source tree | `494cf428a6d6829f132c6b987e3f84a2d14f7485` |
| Cargo.lock SHA-256 | `d6db12262907b2c49a500f26d599c14889540efd2f064dd72cf10fed7bb3de2a` |
| Binary SHA-256 | `c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e` |
| Binary size | 107,042,112 bytes |
| CLI version | `chio-cli 0.1.1-rc.1` |
| Build target and observed system | `aarch64-apple-darwin`, macOS 26.4 on arm64 |
| Compiler | `rustc 1.94.1 (e408947bf 2026-03-25)` |
| Cargo | `cargo 1.94.1 (29ea6fb6a 2026-03-24)` |
| Build interval, UTC | 06:24:38 to 06:57:43 on 2026-09-10 |
| Elapsed build time | 1,984.97 seconds |

The executed build command was:

```sh
cargo auditable build --release --locked --package chio-cli \
  --bin chio --target aarch64-apple-darwin
```

The runner used two Cargo jobs, disabled incremental compilation, and reused
the existing target directory. This was not a cold-cache build. It removed
inherited OpenSSL, dynamic-library and Rust-wrapper/flag overrides before
selecting the target-specific static OpenSSL configuration. The record lists
the actual removed environment keys and selected variables. The source checkout
and all 146 recorded native input identities matched before and after the build;
all 146 also matched when this evidence was collected.

OpenSSL 3.6.4 came from the existing checksum-pinned preparation. The linked
`libssl.a` hashes to
`42069924fa08c872360519b2b2552acbb5f97bf62c642321f87f446461c3e6f3` and
`libcrypto.a` hashes to
`718e86bcdf513257e662647015ae7577ea9e09a478592a1826349e9ccba15882`.
The actual openssl-sys build output identifies version `30600040` and static
linking of both libraries. Its preparation manifest and prior native scan are
retained under `raw/native`; they establish separate native input evidence and
do not establish complete dependency coverage for the Chio executable.

## Actual artifact checks

All three recorded artifact commands exited successfully with their recorded
inputs unchanged. No artifact case is recorded as skipped.

1. The loader gate observed arm64 and nine dynamic dependencies, all under
   `/System/Library/` or `/usr/lib/`. The actual frozen binary returned
   `chio-cli 0.1.1-rc.1` under a sandbox denying reads beneath `/opt/homebrew`,
   `/usr/local`, `/opt/local` and `/opt/pkg`. This is the recorded startup
   observation; it is not a claim about every later runtime access.
2. Syft 1.51.1 scanned the frozen executable into CycloneDX 1.6. Its executable
   SHA-256 was `47cd0bc89537c80eed48f34766743d54574e5830deff243cf54d99696a8e9ce0`.
   The matching archive and upstream checksum inventory are identified in this
   record. Syft emitted a deprecated-cataloger warning; its stderr is preserved.
3. The inventory validator bound the SBOM to the binary and Cargo.lock. It
   reported 742 Rust components, 743 total components and 570 dependency entries,
   including the required CLI, core, guards, kernel and runtime packages. The
   SBOM SHA-256 is
   `5af669eb6b2c01ca59da5a35d509e9a3d3e5faa0d59ea95e917491dadc7f09e6`.

The inventory result has a specific limit: it validates embedded Rust inventory.
It does not establish independently extracted complete graph equality, native
library completeness, or equality with a source/workspace inventory.

The post-build checks used tooling from the execution checkout. The inventory
validator and Syft configuration differ from the versions at the kernel build
source. Their exact recorded bytes are retained under `raw/validation-source`
and match the capture baseline `906c509dfff688817a8b1e5a70d13d97efd3187b`.
This tooling snapshot does not change the kernel's source identity. The build
runner recorded Rust/Cargo versions but did not pin the cargo-auditable
executable hash at execution time. A separately marked retrospective observation
retains its installed 0.7.4 metadata and capture-time binary hash; it is not
promoted to execution-time provenance.

## Reading and verifying the evidence

Every original input file is preserved as deterministic lossless gzip, including
empty stdout/stderr files, the complete build log, runners, build metadata,
artifact outputs, SBOM, and the exact validation source snapshots. `files.json`
records original paths, byte counts, original hashes and compressed hashes.
Those original local paths identify observations; the offline verifier does not
require them or execute the archived runners.

From this directory:

```sh
python3 verify.py
gzip -dc raw/artifact/linkage.json.gz
gzip -dc raw/artifact/validation.json.gz
```

Optionally pass `--binary /path/to/the/frozen/binary` to verify its bytes and
`--repository /path/to/source/checkout` to verify the retained immutable Git
inputs. Neither option builds or executes the kernel. `SHA256SUMS` covers the
complete evidence directory. The credential-exclusion report records comparisons
against known designated provider/operator credentials, using only the scanner's
collection prefix. Its mutable footer was not executed. Product-copy checks
and their existing regression controls are retained under `raw/validation`.

This record preserves local build and artifact observations only. Each real
host, installer path, other target architecture, signed hosted artifact and
published version combination retains its own acceptance requirements.
