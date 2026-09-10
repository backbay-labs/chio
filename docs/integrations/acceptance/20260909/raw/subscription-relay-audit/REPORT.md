# Subscription relay boundary audit, 2026-09-09

This is a read-only audit of five selected integrations, with local fake-upstream HTTP probes. No provider request, real credential, real-host inference, kernel mutation, or repository edit was performed. Cursor's separate protocol blocker is outside this assignment. These results do not accept any host or close Document 19 I01-I08.

## Finding: OpenClaw configured request quota raced across body reads

**Confidence: high. Status: corrected by the OpenClaw owner and independently reprobed.**

At original source `bfabb63efe1267658cc6ef566a3e2dd4a3e42183`, `native/src/model-relay.mjs:61` initializes `remaining=100`; line 67 tests it before line 68's asynchronous body read, and line 70 decrements afterward without a second check. Sending 110 requests with headers first and withholding their bodies lets all 110 pass the early test. Releasing their bodies makes all 110 reach the fake upstream and receive HTTP 200. This defeats an actual configured quota, rather than an inferred requirement.

The owner added a synchronous check/reservation after validation and before either the delivery callback or upstream request (`native/src/model-relay.mjs:71-74` in the corrected snapshot). The unchanged reproducer now admits exactly 100 and refuses 10. No asynchronous operation intervenes between the new test and decrement.

Evidence:

- `openclaw-frozen-before.json`: 110 requests, 110 forwarded, HTTP 200 x110.
- `openclaw-frozen-after.json`: 110 requests, 100 forwarded, HTTP 200 x100 and 403 x10.
- `quota-race-frozen.mjs`: local reproducer using only a fake `fetch` upstream.
- `openclaw-relay-before-source.mjs`: exact original source from the named Git commit.
- `openclaw-relay-source.mjs`: corrected source snapshot, SHA256 `2ae2c174dd5fea0b50f3f8d611498d112bb678520ec0da2289785d8f820dfdc9`.

Reproduce from this directory with Node 25.5.0:

```sh
node quota-race-frozen.mjs ./openclaw-relay-before-source.mjs
node quota-race-frozen.mjs ./openclaw-relay-source.mjs
```

The correction was uncommitted owner work when captured. Its eventual commit and artifact qualification remain the owner's responsibility.

## Other relay observations

The Claude, Codex and Pi relays do not configure or promise a local request-count quota in the inspected implementation. A local 110-request burst forwarded all 110 for each; an output-token request of 1,000,000,000 also reached the fake upstream. These are observations, **not new acceptance failures**. No actual provider acceptance, expenditure or output was tested. Kernel tool-grant budgets and legitimate native model inference remain separate claims.

Sixteen local negative controls across these three relays refused arbitrary `/v1/files` routes, hosted web/MCP tools, remote item/file references, URL-bearing images, background jobs, or previous-response references before fake-upstream forwarding, as applicable to each protocol. See `other-relay-budget-results.json` for every executed case and status. This finite control set is not exhaustive proof against all provider extensions.

Claude intentionally merges the guest's `anthropic-beta` header into the captured native OAuth beta header (`scripts/model-relay.mjs:49`); the local probe observes `audit-required,audit-guest-chosen`. This also appears explicitly in `test/native-login.test.mjs:36`. No arbitrary route or remote tool effect was demonstrated through this header. It is a protocol option that should be included when qualifying a changed host/provider contract, not a newly asserted bypass.

Hermes uses a lock around the remaining-count test and decrement after body validation (`src/chio_hermes/model_relay.py:259-262`), so the OpenClaw check-before-await pattern is absent there. This audit inspected that code but did not rerun a Hermes concurrency host test.

## Credential and route boundary inspection

| Integration | Reviewed boundary | Result and precise source |
|---|---|---|
| Claude | Native parent captures the credential; sandboxed host gets a random local relay token. Fixed Anthropic Messages/count-tokens routes, configured model and custom-tool inventory. | `scripts/native-login.mjs:7-44`; `scripts/restricted.mjs:113-127`; `scripts/model-relay.mjs:30-53`. Parent starts the gateway HTTP transport; the guest gets only its transport token at restricted.mjs:118-122. Sandbox forbids process fork and restricts outbound ports in scripts/sandbox.mjs. |
| Codex | Parent reads explicit native cache and excludes it from readable installation. Fresh isolated profile; only random model/gateway transport credentials passed to child. | `src/cli/restricted.ts:152-171,193-199`; `src/cli/modelRelay.ts:94-103,145-150`. Fixed ChatGPT Codex Responses origin/path and no forwarded guest headers. Hosted tool declarations and account item references rejected. Native apply_patch/client tool-search declarations remain intentionally supported but their actual dispatcher/resource sandbox must retain its separate host acceptance evidence. |
| Pi | Parent reads private native cache; excludes it from profile, installation and workspace. Child configuration has public scope and local transport token, not kernel or provider bearer. | `src/protected-cli.ts:33-34,66,91-104`; `src/model-relay.ts:79-129`; `src/sandbox.ts:38-52`. Fixed origin/route and exact host/origin checks. Stock SDK session disables local builtins, dynamic extensions and project resources; only Chio tool is installed in src/session.ts. |
| Hermes | Parent owns native cache, kernel gateway and model relay. Private paths are rejected if under guest-readable roots. Child gets isolated settings and local tokens only. | `src/chio_hermes/restricted.py:243-248,276-309,400-417`; `src/chio_hermes/model_relay.py:231-275`. Fixed upstream route, exact local Host, no Origin, no arbitrary forwarded headers, no redirects. Hosted tools and account references rejected; encrypted reasoning is dropped. |
| OpenClaw | Parent owns native cache and kernel gateway. Guest is on a private internal Docker network, with separate fixed-route relay container, no host credential/resource mounts, and immutable control volume. | `native/scripts/protected.mjs:16-21,35,69-86`; `native/docker/proxy.mjs:1-18`. Guest config includes local random model/gateway tokens only. Native profile exposes chio_call and disables other tool groups/channels/background features at native/scripts/protected.mjs:74-79 and native/src/profile.mjs. Fixed upstream endpoint and constructed provider headers at native/src/model-relay.mjs:59-60,83-85. |

Inspection did not identify an additional concrete path from a guest-controlled request to arbitrary upstream origin, account CRUD endpoint, hosted remote tool, or operator credential read. This is a bounded source/local-probe conclusion; it does not replace each host's OS/process isolation tests or independently observed protected effects.

## Completed tool errors and acknowledgement

Pi's custom Chio extension emits a `Chio tool completed with an error: ` prefix for a completed resource error. Its owner has added exact prefix normalization before the parent acknowledgement verifier (`src/model-relay.ts:33-45` in the captured corrected source). This audit did not rerun Pi inference.

OpenClaw's plugin returns plain serialized outcome text with `isError=true` (`native/src/plugin.mjs:56`). Its parent parses that text (`native/scripts/protected.mjs:56-67`). The owner's actual native missing-file case in `native/evidence/2026-09-09/native-subscription/tool-error-v5/results.json` was read: one resource dispatch, state completed, acknowledgement true, host delivery confirmed, launcher exit 3. This is explicitly reviewed owner evidence, not an independently executed host test. No same-prefix defect was found for OpenClaw.

## Source and evidence identities

`source-relay-identities.json` records exact relay source heads/hashes used by local probes. `audited-source-identities.json` records the later complete reviewed snapshot, with any dirty paths identified. Heads advanced during the audit, so use the per-file content identities when matching a shipped artifact.

Reviewed snapshot heads:

- Claude: `88c9741415fe1ffca8d192a08a82e52061f3556c`.
- Codex: `bb64e60e1c147caa2e0d50850a560ade188aa4d8` (local probe's unchanged relay was captured at `0e80c6a21655201293ec8aa0b2304db01fee9dce`).
- Pi: `2ccc027b42b837f3df2889863273df2c1e2d5669`.
- Hermes: `476ab366b82e41148da2c8dbd95f405eb29124ab`.
- OpenClaw: `bfabb63efe1267658cc6ef566a3e2dd4a3e42183`, plus explicit dirty quota correction.

All retained source files are below `sources/`. `RESULTS.json` provides machine-readable audit scope and outcomes. `SHA256SUMS` binds these temporary artifacts. No repository commit was made because current ownership authorizes only this temporary audit directory; the parent can retain this record with the program evidence.
