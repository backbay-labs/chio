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

Sixteen focused unit tests pass with zero skips, covering system and non-system
dependency parsing, malformed inventories, target-specific static selection,
bad-source refusal before compilation, preservation of existing directories and
wrong-architecture refusal, and native scan identity, findings, filtering and
database freshness. Synthetic report fixtures exercise validator refusal only.
The two actual binary gate controls are retained.

The coordinating worker independently completed the source-preparation recipe
on Apple Silicon. The upstream test command exited successfully and reported
355 recipe files and 4,046 tests. This is not a zero-skip claim for the upstream
suite: the coordinating worker retains its full logs and skip classification.
The resulting native binary passed the scanner below. The eventual complete
Chio binary, protected-host tests and real installer qualification must remain
explicit in subsequent records. Do not inherit the older candidate's host
results or promote a plain build to a signed release.

The full upstream test log and exact skipped recipe names/reasons are also
retained under `actual-native-scan/`. There are 55 explicit top-level recipe
skips: 25 require a dynamic-engine test harness, eight require external suites,
six require FIPS (including one preparation recipe), three are platform-specific,
two require TCP Fast Open, two require compression, two require allocation-fault
instrumentation, and seven have individual disabled-build-feature reasons.
The FIPS preparation phase reports `Files=1, Tests=0, Result: NOTESTS`; the main
phase reports `Files=355, Tests=4046, Result: PASS`. The captured non-verbose
harness log does not enumerate nested assertion-level skips. Disabled features
and skipped test paths have not been tested by this build, and zero assertion
skips cannot be inferred from the passing main summary.

## Native vulnerability inventory

`scan-macos-release-openssl.py` verifies the prepared source identity, static
library/header hashes, command-log identity and license hash. It downloads a
checksum-pinned Grype 0.118.0 for the native macOS architecture and scans the
actual installed `openssl` executable. Its generated CycloneDX inventory must
contain one OpenSSL component discovered by the binary classifier with the
selected version, CPE and purl, plus the executable's matching SHA-256.

The validator refuses reported or ignored findings, effective ignore/VEX/path
filters, disabled generic CPE matching, an incorrect source, and an invalid or
older-than-120-hour database. It checks the prepared files again afterward.
The controlled configuration enables matching of upstream Linux kernel-header
packages to prevent Grype from adding its four default ignore rules. It uses an
isolated HOME and an explicit configuration with no inherited scanner variables.

```sh
python3 scripts/scan-macos-release-openssl.py \
  --prepared /tmp/chio-openssl-release-build \
  --target aarch64-apple-darwin --output /tmp/chio-openssl-release-scan
```

The [pinned Grype release](https://github.com/anchore/grype/releases/tag/v0.118.0)
is source commit `756eb9a24f7beeafb6871a24e943e8a3ae210695`, with bundled Syft
1.51.1. Archive checksums are pinned separately for both macOS architectures.

The native package probe retains these distinct observations:

- The actual installed OpenSSL 3.6.3 executable is discovered by the scanner,
  which reports 11 vulnerability matches and exits 2. This is a working negative
  control for native package discovery and CPE matching, not a claim that every
  reported path is reachable from Chio.
- The explicitly declared OpenSSL 3.6.4 source-version component yields zero
  matches and zero ignored matches in the same database. This is source-selection
  evidence. It is not a scan of the eventual prepared OpenSSL or Chio executable.
- The database is schema v6.1.9, built 2026-09-09T06:31:00Z; downloaded archive
  SHA-256 `f842f2a17dd4934dca9e1f283ebd7ce397dfcf14cc8a08a8cebb2f5530c131e0`.
  Its installed SQLite bytes hash to
  `3adb9b480e69a184db84652a13973eb2ac8be95683a50e020723aa3c35bc9499`.

Initial probe reports retain Grype's four unrelated default Linux-header ignore
rules, with no ignored matches. Subsequent `controlled-*` reports have an empty
effective ignore list. These records do not label the initial configuration as
unfiltered. No findings were suppressed to obtain a passing OpenSSL result.

The complete native scan helper subsequently passed against the actual prepared
Apple Silicon OpenSSL 3.6.4 executable, SHA-256
`0e33e7613dd8487f3055ce2bcb35f18bb59451293c0d7d9caeacae7a609bf9a9`.
Its discovered catalog, scanner report, controlled configuration and binding
report are retained in `actual-native-scan/`. It reports zero findings and zero
ignored findings. The bound native manifest hashes to
`53ce9d512229466d076ba56302fa7af9960ea78d6a5f5a5295dfb36c2ffebbb2`;
the library inputs are:

- `libssl.a`: `42069924fa08c872360519b2b2552acbb5f97bf62c642321f87f446461c3e6f3`
- `libcrypto.a`: `718e86bcdf513257e662647015ae7577ea9e09a478592a1826349e9ccba15882`

The Intel build, exact complete Chio executable inventory, signed release assets,
and protected-host qualification remain separate required observations.
