# macOS release portability, 2026-09-10

The plain optimized candidate cannot start without this machine's Homebrew
OpenSSL. The actual public 0.1.0 binary starts under the identical denial.
Confidence is high for these directly observed loader results. No installed
library was renamed, removed or changed.

| Artifact | SHA-256 | Normal version startup | Homebrew OpenSSL denied |
| --- | --- | --- | --- |
| Plain optimized 0.1.1-rc.1 candidate | `9f7bc045c97e6c13d9c24641ac426bb61903e3ddab088203a681906ce79d7455` | Pass | dyld abort, signal 6, `libssl.3.dylib` unavailable |
| Actual public 0.1.0 | `c8d7ee8dc4ffdbed4a864b5984f931164a2b320e1a3d914adcb61d0636c354c3` | Pass | Pass |

`loader-comparison.json.gz` preserves the commands, architecture-independent
dependency listing, output and exit status. The sandbox denies both the Homebrew
opt path and its resolved Cellar parent. `check-macos-release-linkage.py` additionally
rejects every non-system Mach-O dependency and unresolved loader-relative path,
checks the target architecture, and starts the binary under denial of all four
common non-system package-manager prefixes. The gate passes the old public
binary and refuses this candidate. These startup controls establish neither
complete runtime confinement nor any host's I01-I08 acceptance.

## Selected repair

Retain the current Rust dependencies and custody/passkey features. Build native
OpenSSL 3.6.4 from its pinned upstream source into a fresh directory, test it, and
link its static archives through target-specific `openssl-sys` variables. The
recipe refuses an existing build directory, mismatched source checksum, wrong
native architecture, failed test command, missing static libraries or dynamic
libraries. Compiler and OpenSSL configuration variables from the operator's
shell are not inherited. There is no installed-library fallback.

The current local library is OpenSSL 3.6.3. The
[25 August 2026 upstream advisory](https://openssl-library.org/news/secadv/20260825.txt)
lists fixes in 3.6.4. This version selection does not claim that every advisory is
reachable through Chio's WebAuthn use or that 3.6.4 has no unknown vulnerabilities.

The source pin is:

- [Upstream OpenSSL 3.6.4 archive](https://github.com/openssl/openssl/releases/download/openssl-3.6.4/openssl-3.6.4.tar.gz)
- SHA-256: `9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef`
- [Upstream checksum](https://github.com/openssl/openssl/releases/download/openssl-3.6.4/openssl-3.6.4.tar.gz.sha256)
- Independently matched [Homebrew formula at commit 53568c8c410e107c15342632fce80f16b6e18a15](https://github.com/Homebrew/homebrew-core/blob/53568c8c410e107c15342632fce80f16b6e18a15/Formula/o/openssl%403.rb).

The downloaded 52.4 MiB archive matches both checksum sources. The retained
formula bytes hash to
`73888fb52f29a58de40f98a52c7bca601dcd5ef478f9b83a845e79b5e9b3aff2`.
This establishes source identity over the fetched authoritative channels; it
does not assert independent cryptographic source review or signature verification.

From the release checkout on an Apple Silicon Mac:

```sh
python3 scripts/prepare-macos-release-openssl.py \
  --target aarch64-apple-darwin \
  --output /tmp/chio-openssl-release-build --jobs 2
. /tmp/chio-openssl-release-build/cargo-env.sh
cargo auditable build --release --locked -p chio-cli --bin chio \
  --target aarch64-apple-darwin
python3 scripts/check-macos-release-linkage.py \
  --binary target/aarch64-apple-darwin/release/chio \
  --target aarch64-apple-darwin --expected-version 0.1.1-rc.1 \
  --output target/aarch64-apple-darwin/release/macos-linkage.json
```

Use `x86_64-apple-darwin` on a native Intel Mac. Python 3.12 or newer, Apple's
command-line developer tools (Clang, make, Perl), Rust, and the pinned release
`cargo-auditable` are build prerequisites. No Homebrew OpenSSL installation is
required by this recipe. It uses `no-shared`, `no-module` and `no-dso`; built-in
crypto remains enabled. It does not deliver dynamically loaded crypto providers
or a FIPS-validated OpenSSL module. See the
[pinned upstream installation instructions](https://github.com/openssl/openssl/blob/openssl-3.6.4/INSTALL.md)
for those native build options.

The generated `native-openssl.json` records source, compiler-command log,
configure options, installed static library/header hashes, and license hash.
Ship the source's `LICENSE.txt` along with the native manifest and actual binary
SBOM. This native manifest is build identity, not vulnerability scanner output
or cargo-vet coverage. Native OpenSSL requires its own inventory/scanner record;
the unchanged Rust lockfile and cargo-vet graph describe the Rust wrappers.

## Validation boundaries

Seven focused unit tests pass with zero skips, covering system and non-system
dependency parsing, malformed inventories, target-specific static selection,
bad-source refusal before compilation, preservation of existing directories and
wrong-architecture refusal. The two actual binary gate controls are retained.

The source-preparation recipe was handed to the coordinating worker for an
independent real build. This record does not claim that its build or upstream
test suite has completed. All upstream failures/skips, the eventual static
binary hash, native scanner result, protected-host tests and real installer
qualification must remain explicit in subsequent records. Do not inherit the
older candidate's host results or promote a plain build to a signed release.
