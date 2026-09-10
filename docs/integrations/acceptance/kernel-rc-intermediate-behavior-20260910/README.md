# Intermediate kernel candidate behavior, 2026-09-10

**No integration is accepted by this record.** It preserves successful bounded
runs and the failed initial Claude workflow against one unpublished optimized
kernel. Document 19 in the authoritative planning worktree still requires all
six hosts to complete I01-I08. Confidence in the recorded local observations is
high; complete acceptance and usable delivery remain unresolved.

The kernel is `chio-cli 0.1.1-rc.1`, source
`ae12bb2a6f7dbf875188ce357314654de440ddc3`, binary SHA-256
`9f7bc045c97e6c13d9c24641ac426bb61903e3ddab088203a681906ce79d7455`
(107,042,128 bytes). The plain release build used Rust/Cargo 1.94.1 on macOS
26.4 arm64, Cargo.lock SHA-256
`d6db12262907b2c49a500f26d599c14889540efd2f064dd72cf10fed7bb3de2a`,
and completed at 05:29:27 UTC. Its test-driver checkout was a later source
revision, recorded separately in each `identity.json.gz`; those revisions do
not change the binary's build identity.

This binary is unsuitable for release. It dynamically depends on Homebrew's
OpenSSL libraries and fails the separate loader test when those libraries are
unavailable. The plain build also lacks cargo-auditable dependency metadata:
the retained actual Syft 1.18.1 negative control exits zero and emits a
CycloneDX 1.6 document with **zero dependency components**. A schema-valid empty
inventory does not qualify the binary. Portable dependency packaging, meaningful
binary inventory, source gates, signing and release provenance remain required.

## Observations and failures

| Evidence group | Executed observation | Outcome |
|---|---|---|
| `plain-shared` | 11 shared kernel suites: replay, actual capability expiry, cancellation/unknown after dispatch, approval artifacts/workflows, individual and parallel aggregate budgets | All 11 passed; these are direct kernel boundary fixtures, not real-host acceptance |
| `plain-native` | One native four-tool useful workflow per host: write, edit, read, list | Codex, Pi, Hermes and OpenClaw passed with four independent dispatches and four confirmed deliveries each; original Claude failed |
| `plain-matrix` | 33 driver commands independently per Claude, Codex, Pi, Hermes and OpenClaw, using the original plugin archives below | All 165 commands passed; no matrix skip recorded |
| `claude-contract-matrix` | Replacement Claude archive: three setup commands, one four-tool useful workflow, then the same 33 matrix commands | All 37 commands passed; 37 is a command count, not 37 distinct acceptance tests |
| Cursor | No run in these groups | Required and unresolved; no skipped-pass substitution |

The initial Claude failure is retained under
`plain-native/claude/useful/`. The host made exactly one `write_file` call to
`/workspace/claude-qualified-fd7fe194274242a6.txt`, writing
`Claude native original\n`. The independent observer recorded one dispatch and
the original 23-byte content; one delivery was confirmed. The returned text
masked part of the numeric filename after two `pii_ssn_compact` findings. Claude
then stopped, describing the sanitized result as uncertain, and never made the
required edit, read or list calls. The assertion was
`Expected exact real native tool call absent: edit_file`. A process exit of zero
and a completed individual write did not pass the requested workflow.

The replacement archive's launcher instructions explain the verified result
contract, including sanitized output and use of already-known original request
arguments. Its useful workflow completed all four requested calls with four
resource observations. This is a separate artifact and run; it does not erase
the original failure. A later metadata-only Claude archive is also a different
artifact and receives no acceptance transfer from this record.

Each 33-command matrix contains 24 base suites, six original-session resume
fences after kernel/evidence faults, and three explicit signed-owner recovery
suites. Base suites cover forbidden read/write/edit, alternate file operations
and paths, approvals, revocation, in-flight capability/credential revocation,
kernel kill/malformed/timeout/absence, expired session credentials, wrong
principal/session/resource, scope escalation, three evidence substitutions,
and concurrent owners. Some invalid configuration cases are refused by the
actual launcher before the host starts, explicitly recorded in the raw result.
They are not described as model-generated tool attempts.

Native tool-call records, host output and before/after resource observations are
retained. Fault injection and operator recovery run in the trusted test parent;
resource observations come from separate resource/audit volumes. Where Claude
needs a declared tool choice for a negative case, the real provider receives
that tool choice and the raw record states that arguments and assistant output
were not fabricated. Shared-kernel fixtures remain separately labeled.

## Selected identities

| Host/run | Integration package | Archive SHA-256 |
|---|---|---|
| Original Claude | `@chio/claude-code-plugin` 0.3.0 | `0dd0d906fc34b3ac7d09e3b7f6cdee9f13f511731b25ec761feca7172c9b1158` |
| Replacement Claude | `@chio/claude-code-plugin` 0.3.1-rc.1 | `28e8757429548e8fdcb1ffa3c3c665f8eafde426d7ba5f6807086123d6d07646` |
| Codex | `@chio/codex-plugin` 0.3.0 | `ac4f14ee4073abdc0c9ff2b4771e99adf7a871d084a9b488513f5d28eae56874` |
| Pi | `@chio/pi-plugin` 0.1.0 | `ec6095390b9eae233540b73aee0ad2fef6977c36122dd30aa2779329b1897aa1` |
| Hermes | `chio-hermes` 0.1.2 wheel | `625979d5331796e7aef5906e69e3e2c746796aa570291af026c305ed4227c818` |
| OpenClaw | `@chio/openclaw-kernel` 0.1.0 | `a79dbffa8356a608f22db847e100d1989cb7ff322ab1315144774decb2b13ab4` |

Claude's native binary was 2.1.267, SHA-256
`a681f3008f0050029aeebcab3af51bb6a55ddeb625a3af3141a4416d43cd2558`,
using `claude-sonnet-5` and native Claude login. Codex was 0.153.4, SHA-256
`b973d440acac501fd2594a43e7ca9ce41e0a65b9dfb28d0d7a7837c99e1261e3`,
using `gpt-5.5` and its native ChatGPT cache. Pi's public peer package was
`@earendil-works/pi-coding-agent@0.85.1`. Hermes' host source revision was
`175054c14b54404663d8614a178280cffe6062eb`. Pi, Hermes and OpenClaw used
`gpt-5.5` through the native Codex subscription transport. Host commands,
configuration hashes, session identities, gateway hashes, SDK and bridge
identities where measured are in the per-run raw identity and launch records.

All runs used the protected filesystem image
`sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
OpenClaw's separate native host image was
`sha256:7f925d68ced724f4a6314ab76dc117e9000515ba62149ee971a11c510be6637f`.
This record does not qualify the legacy hosted chat gateway.

The cold installation records verify all regular files in each selected npm
archive against installed bytes: Claude 1,227, Codex 2,337, Pi 1,090 and OpenClaw
1,075. Hermes verifies 18 adapter and 1,052 bridge files. Pi first installs its
public pinned host peer with nested dependency placement, then the plugin;
there is no claim of a plugin-only offline install. Local archive installation
establishes candidate packaging behavior, not publication or a finished public
installation path.

## Canonical delivery infrastructure

At 06:22:19 UTC the operator enabled Actions on the canonical public
`backbay-labs/chio` repository so its existing source and release workflows can
produce evidence in that repository. `public-actions-enablement` preserves the
before/after API reads, command exit status and operator change record. The
before response has `enabled: false`; the after response has `enabled: true`.
This action changes workflow availability, not a source-check result. No branch
protection, workflow content, signing requirement or required gate was relaxed
by this operation. Exact-source successful runs remain separately required.

## Required final work

The eventual immutable kernel, plugin and SDK combination must receive its own
complete per-host I01-I08 record. In particular, rerun useful work and the full
matrix above against the portable auditable binary and final selected archives.
Also complete each host's native confinement and unsupported-path tests,
plugin failure/omission controls, actual capability expiry and aggregate budget
cases, host lifecycle and restart cases, storage/signing cutpoints, installation,
upgrade, recovery and removal. Shared direct kernel tests do not replace these
host tests. Required cases that are absent here remain unresolved rather than
implicitly passed.

Publish compatible artifacts only after their applicable source, security and
release gates pass, then verify the documented public installation path without
private sibling source dependencies. Cursor still needs an established
server-enforced restriction for consequential remote actions before its real
host matrix can proceed. All six hosts remain mandatory. These records make no
independent adoption or research novelty claim and do not modify the selected
candidate manifest.

## Evidence verification

Every raw file is stored as deterministic lossless gzip. `files.json` records
its compressed SHA-256, original SHA-256, original byte count and original local
source path. Paths identify where observations came from; they are not public
installation prerequisites. `export-inputs` preserves the original 171-file
staging manifest and its earlier credential check. The final export has 3,340
raw files: those 171 originals, two staging metadata files, 2,581 five-host matrix
files, 580 replacement-Claude files, four canonical Actions records and two
validation logs.

`credential-exclusion.json` reports comparison of every uncompressed raw file
against known provider, npm, operator and delegated-session credentials. Private
databases, signer seeds and raw operator journals are excluded. Sanitized
`journal-states.json` projections, signed owner outcomes, public identities and
request-bound delivery acknowledgements are preserved as test observations.
No provider/operator credential value is exported. Historical raw output remains
byte-exact, including erroneous model interpretations and failed assertions;
it is evidence, not authored product claims.

From this directory, run `python3 verify.py` to verify the checksum inventory,
every decompressed byte identity, and the recorded command/skip/failure counts.
Use `gzip -dc plain-native/claude/useful/results.json.gz` to inspect the original
failed workflow. This verifier does not rerun a host or convert these bounded
observations into acceptance. The unchanged repository product-copy gate and
its negative controls are recorded under `validation`.
