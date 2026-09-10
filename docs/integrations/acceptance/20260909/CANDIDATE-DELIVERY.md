# Local candidate delivery

## Current static candidate, 2026-09-10

The current local bundle is
`/Users/connor/.local/share/chio-required-candidates/required-agents-static-rc-local-20260910-r3.tar.gz`,
518,088,554 bytes, SHA256
`25750f19f27ad49793df9a0ae72ab55b920ffb544cb0fa426e9e80ee453de5b9`.
It selects kernel `0.1.1-rc.1`, SHA256
`c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e`,
and Claude `0.3.1-rc.1`, SHA256
`1258385647d228ebeed32662091ed721aeda3b60450cabae480ca0d4292fbe0a`.
Its manifest binds the other integration, SDK, bridge and image identities.

Extract with system `tar` into a new directory to preserve the archive's recorded
file modes. Python 3.14's default data extraction filter changes those modes and
the bundle verifier correctly refuses that extraction. Follow the extracted
`README.md`; its source and local verification are retained at harness commit
[`6d49d48c478967e518c052c628e59a7183ff9814`](https://github.com/backbay-labs/chio-test-harness/blob/6d49d48c478967e518c052c628e59a7183ff9814/delivery/OPERATOR.md).

Cold installation, useful resource work, explicit credential/capability revocation
and zero subsequent dispatch passed using the shipped procedures. The final r3
archive changes only the README's session-expiry recovery explanation relative
to that operationally tested r2 archive; the other 48 selected entries and the
executed revocation snippet are byte-identical. The r3 archive itself passed cold
extraction, checksum, image and CLI identity checks. The
[readiness record](../prepare-session-readiness-20260910/actual-cold-successor/README.md) retains the
original startup failure and the corrected operation. No private operator state
is included in the bundle.

Status remains **0/6 accepted**: Cursor's server enforcement contract is unresolved,
and compatible public artifact delivery and final release qualification remain
open. This local archive is usable qualification delivery, not a published release.
The older bundle and commands below are historical evidence and do not select
the current kernel or Claude archive.

## Historical candidate delivery, 2026-09-09

Status: **0/6 integrations accepted**. This directory provides the exact local
qualification artifacts, not a public release. Do not install the historical
public CLI and assume its `0.1.0` label identifies this kernel. Select the hash.

Retained bundle:
`/Users/connor/.local/share/chio-required-candidates/20260909`

The bundle contains the selected macOS arm64 kernel, all six integration
candidates, bridge and SDK archives, the complete Hermes adapter wheelhouse,
resource-owner source/policy, and the exact tested filesystem and OpenClaw Docker
images. It contains no operator credentials, normal host profiles, or resource
volumes. Host applications are separate upstream prerequisites. The manifest
identifies artifacts; the host records identify bounded tests and remaining gaps.

## Current candidates and unresolved gates

Native subscription authentication is working for Claude Code, Codex, Hermes,
Pi and OpenClaw. Each has performed actual kernel-mediated file work with its
host-supported provider. Cursor's isolated CLI login also works. No new API key
or MFA is currently needed for these profiles. The old API-credit failures and
superseded artifacts remain retained, but are not current authentication blockers.

The manifest selects immutable local candidates by SHA256. The preceding
selection, manifest and instructions remain under `superseded/pre-native-subscriptions`.
Do not combine tests across these archives. Claude r5 is source `c91cd81`, archive
`0dd0d906fc34b3ac7d09e3b7f6cdee9f13f511731b25ec761feca7172c9b1158`.
The current replacements repair Claude native initialization and unsuccessful-result reporting, Pi's
completed tool-error acknowledgement and OpenClaw's concurrent model-request
limit. Their regressions, broad host matrices and launcher journal/cancellation
cutpoints pass. Claude, Codex, Hermes, Pi and OpenClaw also completed their own
actual kernel admission and receipt-storage failure cases, with original-authority
retry/restart fencing and independent resource observations. No archive is accepted.

Public draft source PRs and captured hosted checks are recorded in
[the source and CI checkpoint](PUBLIC-SOURCE-AND-CI.md). Five standalone plugin
source CI runs and the shared harness passed; bridge CI was still running at the
2026-09-10 04:07 UTC snapshot. Successful checks used synthetic PR merges whose
Git trees match the recorded source heads. Hermes remains in the separate ARC
source/release lane. These source
checks do not replace the [kernel release-readiness gates](../kernel-release-readiness-20260909/README.md),
Cursor's missing enforcement contract, or compatible-combination publication.
The selected 48-entry artifact manifest remains a local candidate selection.
Released storage-test owners were stopped without deleting databases, journals,
credentials, unknown outcomes or resource/audit volumes; this bundle includes
none of those private owner states.

Cursor protected prompt mode refuses before starting the host. Its server-owned
messaging, cloud/agent management and PR mutation paths require a supported
pre-dispatch restriction. Local permission flags and after-effect notifications
do not establish that boundary. Authentication is no longer its blocker.

The exact version combination has not passed all I01-I08 and release gates;
this bundle is local qualification delivery, not an accepted public release.

## Verify and install

From the retained bundle directory:

```sh
shasum -a 256 -c SHA256SUMS
docker image load --input images/filesystem-owner.tar
docker image load --input images/openclaw-host.tar
npm install --prefix install/bridge --offline --ignore-scripts packages/chio-bridge-0.3.0.tgz
npm install --prefix install/codex --offline --ignore-scripts packages/chio-codex-plugin-0.3.0.tgz
```

Claude, Cursor and OpenClaw use the corresponding archive in `packages` with a
separate installation prefix. Those archives bundle their runtime dependencies;
no sibling source checkout is needed. Use an empty `--cache` directory to repeat
the cold-install check. The original source trees are not install dependencies.

Pi requires its public, exactly pinned upstream peer package. Its documented
installation needs registry access; the plugin-only offline command fails with
`ENOTCACHED` on an empty cache. Use both steps in the same prefix:

```sh
npm install --prefix install/pi --ignore-scripts --install-strategy=nested \
  @earendil-works/pi-coding-agent@0.85.1
npm install --prefix install/pi --ignore-scripts --install-strategy=nested \
  packages/chio-pi-plugin-0.1.0.tgz
```

This is a public upstream dependency, not a private sibling checkout. The exact
plugin archive's README contains the same two-step procedure.

Hermes adapter installation, using the Python 3.11 macOS arm64 runtime selected
in its host record:

```sh
python3.11 -m venv install/hermes
install/hermes/bin/python -m pip install --no-index --no-cache-dir \
  --find-links hermes-wheelhouse chio-hermes==0.1.2
install/hermes/bin/python -m pip check
npm install --prefix install/hermes-bridge --offline --ignore-scripts \
  packages/chio-bridge-hermes-0.3.0-b7785282b4f4.tgz
```

Hermes itself must be the separately pinned public upstream checkout and host
runtime described in its acceptance record. Pi's upstream host library is
installed separately by the two commands above. OpenClaw's exact runtime and plugin are in
the retained host image. Claude, Codex and Cursor require their pinned native
executables; arbitrary upgrades are refused or unqualified.

## Start a disposable resource owner

Choose a new private state directory, unused `chio-required-` volume name and
unused loopback port. The command refuses an existing state or volume. Example,
from the bundle, after creating the private parent directory:

```sh
python3 resource-owner/serve-filesystem.py start \
  --state-dir /absolute/private/new-owner \
  --kernel "$PWD/bin/chio" \
  --kernel-sha256 33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25 \
  --image sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0 \
  --volume chio-required-new-owner \
  --port 58510
python3 resource-owner/prepare-session.py \
  --operator-state /absolute/private/new-owner \
  --bridge "$PWD/install/bridge/node_modules/@chio/bridge"
```

Preparation prints the private gateway configuration path. It grants new test
work with a 15-minute session credential, four file tools and one shared
64-invocation capability. It performs no resource action. Keep that exact
configuration and authority for retries and recovery. Preparation is **not** a
way to clear uncertainty or replenish an exhausted/revoked grant.

## Launch the selected host

Use the package's supported launcher, not a normal host session with advisory
hooks. The following files are inside the corresponding installed package:

| Host | Launcher | Configuration and procedures |
|---|---|---|
| Claude | `scripts/restricted.mjs` | `docs/RESTRICTED-MODE.md`; pinned executable/gateway hashes, new profile/workspace and private gateway config. use `--model-auth claude-login` with the native operator login; credentials stay in the trusted parent |
| Codex | `dist/cli/main.js restricted` | `RESTRICTED.md`; private gateway config, pinned Codex binary, new evidence directory and prompt; use `--model-auth-file /absolute/private/codex-auth.json`; the native ChatGPT credential stays in the parent |
| Cursor | `bin/chio-cursor-protected.mjs --probe` | `OPERATIONS.md`; pinned extracted CLI and private gateway config. Only discovery works. Protected prompt mode deliberately refuses pending the server enforcement contract and hosted-protocol qualification |
| Hermes | `python -m chio_hermes.restricted` | Adapter `README.md`; pinned host Python/source, installed bridge, private gateway config, new state and query file; `--model-auth codex-subscription --codex-auth-file /absolute/private/codex-auth.json --model gpt-5.5` |
| Pi | `dist/protected-cli.js` | `README.md`; private config, new profile/workspace, `--provider openai-codex --model gpt-5.5 --codex-auth /absolute/private/codex-auth.json` and prompt |
| OpenClaw | `scripts/protected.mjs` | `README.md`; private config, new state and `--model-auth-file /absolute/private/codex-auth.json` and immutable host image selected by the manifest |

For example, after preparing a session and selecting a new evidence directory:

```sh
node install/codex/node_modules/@chio/codex-plugin/dist/cli/main.js restricted \
  --gateway-config /absolute/private/new-owner/new-session-ID/gateway.json \
  --codex-binary /absolute/pinned/codex \
  --evidence-dir /absolute/private/new-evidence \
  --model-auth-file /absolute/private/codex-auth.json \
  --prompt 'Use Chio to write /workspace/example.txt, then read the same remote file.'
```

The selected native Codex auth cache must be an operator-owned regular mode-0600
file outside guest/profile/workspace/install trees. Use a designated private cache
initialized or refreshed by the native Codex CLI. Do not manually refresh or expose
its OAuth tokens. A login in the ordinary CLI alone does not activate the protected
launcher: select this explicit parent-only auth argument. Claude's native-login
helper uses the operator's existing native login without copying its credential
into the guest. Remove an inherited alternate `ANTHROPIC_BASE_URL` before using
Claude subscription mode; only the fixed native endpoint is permitted.

No credentials are embedded in this document or bundle. The profile implements
remote file work; shell, arbitrary networking, delegation and other unsupported
consequential paths remain disabled or confined in the selected host mode.

## Recovery, upgrade and removal

Read each host's terminal outcome and independent resource observation. A host
turn completing does not establish a successful protected effect. Unknown or
unacknowledged outcomes retain their original operation and authority. The
installed bridge operator CLI supports `delivery-export`,
`delivery-acknowledge` and `recover-lock`. Inspect the exact exported result
before acknowledgement. Recover a lock only after its recorded owner is dead.
Never delete the journal, replace the session, or automatically redispatch an
unknown operation. Approval decisions use the exact pending request descriptor.

If the host retained an unknown operation but the owner retained its signed
completion, install the separately shipped operator bridge. It uses the same
kernel contract; host runtime bridge archives stay at their qualified identities:

```sh
npm install --prefix install/operator-bridge --offline --ignore-scripts \
  packages/chio-bridge-operator-0.3.0-02a0e4ad4e61.tgz
python3 resource-owner/export-owner-outcome.py \
  --operator-state /absolute/private/original-owner \
  --gateway-config /absolute/private/original-owner/original-session/gateway.json \
  --request-id ORIGINAL_REQUEST_ID \
  --output /absolute/private/new-owner-result.json
node install/operator-bridge/node_modules/@chio/bridge/dist/gateway-operator.js \
  owner-result-import /absolute/private/original-owner/original-session/gateway.json \
  /absolute/private/new-owner-result.json
node install/operator-bridge/node_modules/@chio/bridge/dist/gateway-operator.js \
  delivery-export /absolute/private/original-owner/original-session/gateway.json \
  ORIGINAL_REQUEST_ID /absolute/private/new-received-result.json
```

Stop the host before import. Use `recover-lock` only for a proven dead owner.
The exporter reads the exact session/request row without network dispatch. Import
verifies its signature, original authority, request and complete result; it keeps
the previous journal state and outcome and leaves the completion fenced and
unacknowledged. A pending record can have no previous outcome after its local
completion write failed; import preserves that fact.
Read the exported result and compare the independent resource observation before
acknowledging it explicitly:

```sh
node install/operator-bridge/node_modules/@chio/bridge/dist/gateway-operator.js \
  delivery-acknowledge /absolute/private/original-owner/original-session/gateway.json \
  /absolute/private/new-received-result.json
```

Missing, pending, invalidly signed or mismatched owner records leave uncertainty
unresolved. The procedure cannot renew expired or revoked authority. No step
redispatches the original tool action. A failed acknowledgement keeps the fence.

`serve-filesystem.py stop --state-dir ...` stops the selected owner and preserves
its databases and volumes. `restart --state-dir ...` checks the retained kernel
and policy hashes before starting the same owner. Neither command is a database
migration or a qualified kernel upgrade. Keep the old artifact, policy, journal,
receipts and resource until an upgrade has passed its own required tests.

Revoke the session credential and capability before removing a host profile.
Stop its parent launcher and resource owner; retain required receipts and
unknown-outcome state. Remove only explicitly designated disposable profiles,
install prefixes and volumes after inspection. No normal-home cleanup script is
provided. Current five working hosts have bounded upgrade/removal and
in-flight-failure evidence. Cursor and public release qualification remain open,
so this bundle must not be described as accepted lifecycle delivery.

The selected Claude and OpenClaw packages include trusted launcher-death
supervision. Their replaced artifacts and the previous OpenClaw image remain in
`superseded/pre-host-supervision`, outside the active installation manifest.
The new artifacts passed their own forced-crash recovery checks. Earlier Claude supervision tests used a local model fixture; those observations
remain separate from current authenticated subscription runs. Current-artifact
crash and recovery observations are named in each host record. Preserved volumes and unknown outcomes still require explicit
operator recovery. A watchdog cleanup error is unresolved, not successful
removal. Each new artifact requires its own evidence; historical observations
do not qualify an upgrade.

Hermes r15 uses the separately retained `hermes-bridge` archive above. Pass
`install/hermes-bridge/node_modules/@chio/bridge/dist/gateway-http.js` to its
launcher. This pins the exact bridge used in its native qualification, while
the other integrations retain their own tested bridge builds. The previous r9
wheel and manifest remain under `superseded/hermes-r9`. The selected r15 wheel
handles operator SIGTERM/SIGINT, reaps the isolated process group and reports an
unacknowledged committed result as unresolved. Its current record includes
separate SIGKILL, startup, native-history and upgrade/removal cases.
