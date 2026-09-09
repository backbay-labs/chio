# Local candidate delivery

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

## Verify and install

From the retained bundle directory:

```sh
shasum -a 256 -c SHA256SUMS
docker image load --input images/filesystem-owner.tar
docker image load --input images/openclaw-host.tar
npm install --prefix install/bridge --offline --ignore-scripts packages/chio-bridge-0.3.0.tgz
npm install --prefix install/codex --offline --ignore-scripts packages/chio-codex-plugin-0.3.0.tgz
```

For other TypeScript hosts, select the corresponding archive in `packages` and
use a separate installation prefix. Archives bundle their runtime dependencies;
no sibling source checkout is needed. Use an empty `--cache` directory to repeat
the cold-install check. The original source trees are not install dependencies.

Hermes adapter installation, using the Python 3.11 macOS arm64 runtime selected
in its host record:

```sh
python3.11 -m venv install/hermes
install/hermes/bin/python -m pip install --no-index --no-cache-dir \
  --find-links hermes-wheelhouse chio-hermes==0.1.2
install/hermes/bin/python -m pip check
```

Hermes itself must be the separately pinned public upstream checkout and host
runtime described in its acceptance record. Pi's upstream host library is
bundled in the integration archive. OpenClaw's exact runtime and plugin are in
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
| Claude | `scripts/restricted.mjs` | `docs/RESTRICTED-MODE.md`; pinned executable/gateway hashes, new profile/workspace and private gateway config. Isolated Anthropic credential remains missing for real provider acceptance |
| Codex | `dist/cli/main.js restricted` | `RESTRICTED.md`; private gateway config, pinned Codex binary, new evidence directory and prompt; operator OpenAI credential stays in parent |
| Cursor | `bin/chio-cursor-protected.mjs --probe` | `OPERATIONS.md`; pinned extracted CLI and private gateway config. Only discovery works. Protected prompt mode deliberately refuses pending isolated authentication and hosted-protocol qualification |
| Hermes | `python -m chio_hermes.restricted` | Adapter `README.md`; pinned host Python/source, installed bridge, private gateway config, new state, query file and fixed provider route |
| Pi | `dist/protected-cli.js` | `README.md`; private config, new profile/workspace, OpenAI provider/model and prompt |
| OpenClaw | `scripts/protected.mjs` | `README.md`; private config, new state and immutable host image `sha256:1586b295831a811e4ba890fe466e9397bc44eeff9b77fa41ae740cc845eb4c2d` |

For example, after preparing a session and selecting a new evidence directory:

```sh
node install/codex/node_modules/@chio/codex-plugin/dist/cli/main.js restricted \
  --gateway-config /absolute/private/new-owner/new-session-ID/gateway.json \
  --codex-binary /absolute/pinned/codex \
  --evidence-dir /absolute/private/new-evidence \
  --prompt 'Use Chio to write /workspace/example.txt, then read the same remote file.'
```

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

`serve-filesystem.py stop --state-dir ...` stops the selected owner and preserves
its databases and volumes. `restart --state-dir ...` checks the retained kernel
and policy hashes before starting the same owner. Neither command is a database
migration or a qualified kernel upgrade. Keep the old artifact, policy, journal,
receipts and resource until an upgrade has passed its own required tests.

Revoke the session credential and capability before removing a host profile.
Stop its parent launcher and resource owner; retain required receipts and
unknown-outcome state. Remove only explicitly designated disposable profiles,
install prefixes and volumes after inspection. No normal-home cleanup script is
provided. Complete upgrade/removal and in-flight-failure qualification remain
open, so this bundle must not be described as accepted lifecycle delivery.

The selected Claude and OpenClaw packages include trusted launcher-death
supervision. Their replaced artifacts and the previous OpenClaw image remain in
`superseded/pre-host-supervision`, outside the active installation manifest.
The new artifacts passed their own forced-crash recovery checks. Claude tests
used an actual native host with a local model fixture; authenticated Anthropic
qualification remains open. OpenClaw tests used its actual native host and
OpenAI service. Preserved volumes and unknown outcomes still require explicit
operator recovery. A watchdog cleanup error is unresolved, not successful
removal. Earlier startup/crash cutpoints and full lifecycle acceptance remain
open.
