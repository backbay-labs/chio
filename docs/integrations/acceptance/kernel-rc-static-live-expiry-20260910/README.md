# Static kernel supplemental live-expiry observations

This record preserves bounded real-host authority-expiry observations and their original failures. It does not accept a host, establish all I01-I08 gates, or publish a release. Document 19 remains the program's acceptance authority; all six selected integrations remain mandatory.

Seven host-case executions are retained: four bounded passes and three original failures. These are four host-specific expiry observations, not four accepted integrations.

| Raw input group | Host cases | Recorded result |
| --- | --- | --- |
| `original-mac-hosts` | Codex, Pi, Hermes | Codex passed; Pi and Hermes failed native-result parsing |
| `mac-hosts-r2` | Pi, Hermes | Both passed with fresh native requests |
| `original-openclaw` | OpenClaw | Failed native/kernel request-ID assertion |
| `openclaw-r2` | OpenClaw | Passed with newly observed HTTP-session binding |

No case is skipped. Start/case/stop commands in the successful runs all exited zero; the three failed cases retain their nonzero case status and subsequent identity-checked stop records. Databases, journals, fences and resource volumes were preserved. This archival work launched no host or owner and stopped no process.

## Observed behavior and limits

Each case asks the native host to write an allowed file, then issue a second write to the same path. The fixture holds that second actual request at the gateway transport until the owner-issued capability and its clamped session credential have expired, then forwards the original request to the kernel. The first write must complete and reach the resource. The second must receive a real kernel HTTP 401 while the original contents remain and the independent resource observer records no second dispatch.

The expired call remains `unknown` and unacknowledged in the gateway observation because it lacks signed execution evidence. This is HTTP authority refusal after expiry. It is not a signed `CapabilityExpired` admission receipt or a claim that the host received such a receipt. The record preserves the native host's actual error representation and any difference between a guest request identifier and its kernel namespace identifier.

The original Pi and Hermes executions failed the fixture's strict native-envelope cardinality assertion. Their raw failures remain failures even though the kernel and resource observations satisfied the expiry conditions. Fresh executions use a corrected parser for the native error forms. The first OpenClaw execution separately failed a strict request-ID assertion; its raw failure also remains a failure. No historical output is rewritten or reclassified.

Successful reruns must each retain two native calls, one completed authorized resource dispatch, the same second request held before expiry and forwarded after expiry, kernel HTTP 401, no second resource dispatch, unchanged file contents, and a request-bound unacknowledged unknown outcome. The per-run records are the evidence; a parser unit test alone does not satisfy those conditions.

Pi returns a native error message without a request ID; its binding is the native tool-call ID and exact arguments, with the request-qualified unknown in the journal observation. Hermes returns an error envelope containing the kernel request ID. OpenClaw retains native `isError: false` and an `unknown/unverified` envelope identified by its guest operation ID. Its fresh record observes the gateway's initialized HTTP session and recomputes both native-call-to-guest and guest-to-kernel mappings. None of those native error forms is rewritten to look like another host's response. The original OpenClaw run lacks the HTTP-session observation and remains unqualified.

## Artifact identities

All included host executions use kernel source `bafa02b06de93553cecb6f60b340f3dd8fd9b401`, version `chio-cli 0.1.1-rc.1`, and binary SHA-256 `c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e`. The audited filesystem image is `sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`. OpenClaw uses image `sha256:7f925d68ced724f4a6314ab76dc117e9000515ba62149ee971a11c510be6637f`.

| Integration | Selected artifact | SHA-256 |
| --- | --- | --- |
| Codex | `@chio/codex-plugin@0.3.0` | `ac4f14ee4073abdc0c9ff2b4771e99adf7a871d084a9b488513f5d28eae56874` |
| Pi | `@chio/pi-plugin@0.1.0` | `ec6095390b9eae233540b73aee0ad2fef6977c36122dd30aa2779329b1897aa1` |
| Hermes | `chio_hermes-0.1.2-py3-none-any.whl` | `625979d5331796e7aef5906e69e3e2c746796aa570291af026c305ed4227c818` |
| Hermes bridge | `@chio/bridge@0.3.0` archive | `b7785282b4f4e4da42e4158c7390a2d1411ba2763b01956b07896aadf6dcc6d9` |
| OpenClaw | `@chio/openclaw-kernel@0.1.0` | `a79dbffa8356a608f22db847e100d1989cb7ff322ab1315144774decb2b13ab4` |

Codex's native launch record identifies version `0.153.4` and binary SHA-256 `b973d440acac501fd2594a43e7ca9ce41e0a65b9dfb28d0d7a7837c99e1261e3`. Pi's installed public peer is `@earendil-works/pi-coding-agent@0.85.1`; its registry cache archive and installed regular members were compared after the original executions. Hermes uses public source commit `175054c14b54404663d8614a178280cffe6062eb`, tree `b485d3e994bda896e30ba7e3216aadb641b1d8e3`, and Python 3.11.3 binary SHA-256 `c220ae7b6c2b9da2a4e498c09cdbc64b03b43db96dbbf9f64d26bfbbd698e2bd`. The archive retains exact commands, model selections, paths and native launch records where emitted.

## Source and installation provenance

The initial macOS batch records fixture source `7df0bd46d841e20f1e767e5ff79d9fdfb5937dc6`, production source `3b523ebf2fba0c3931d6d45867aa3d4fcd5be47a`, 15 named source snapshots and before/after equality for those named sources and the kernel binary. Its driver does not compare the complete installed packages before the run. Subsequent post-run comparisons do not retroactively establish that missing pre-run check.

The Pi/Hermes rerun and first OpenClaw attempt record fixture source `c992250a2c47f943e2a6a488a74332cf608d5c50`, production source `0181dec9619b99b9b8faf65397a4aa5733cbd145`, and 16 named source snapshots, including `live_expiry_native.py`. Their enhanced driver compares selected plugin archive members before and after, checks image IDs, and verifies Hermes's selected bridge, 22 wheel files excluding the installed RECORD, public source HEAD with no tracked changes, and Python binary hash. Those checks have the exact scope stated by the driver; they do not recursively attest every interpreter, sibling import or package not present in the compared archive. The driver copies its own bytes once and does not check its own before/after equality.

The successful fresh OpenClaw run records fixture source `0a57ac30a6490ec27034cfa4d3ac9093b12ffffb` and production source `bfcf0170b6fa69891a3feb1d7205889eb63232b7`, with the same enhanced driver and 16 source snapshots. Its updated fixture records the actual gateway HTTP initialization and native namespace mappings. Both before/after installation reports match. The separate `binding-repair-controls` input preserves 25 development controls and five archive/installed/image file comparisons; these support fixture review and are not additional real-host cases.

`binding-repair-followup` is a later complete snapshot of that development folder after one public-session audit was added; its seven repeated files remain identical. The audit binds the session observation to the three fresh OpenClaw raw files and the frozen gateway source. Its seven allowed diagnostic fields contain no authorization header or request body. The initialized MCP session identifies the connection; the gateway independently requires a bearer credential before parsing the request and session. The session identifier alone does not authorize execution.

The separate post-run review compared 8,893 regular members across seven archives: the four selected npm integrations including Claude, two bridge archives and the Pi public native peer archive. It also compared 18 Hermes adapter package files, four kernel/native executable hashes, and Hermes's public source HEAD/tree, tracked diff, lock and project-file hashes. Claude is included only in this installation comparison; this folder contains no Claude live-expiry execution. OpenClaw's image is recorded by the post-run review but was not re-inspected during that review, which launched no Docker or host process. The historical driver records its own image checks separately.

## Preservation and verification

`files.json` binds every raw gzip file to its original absolute source path, original byte length, original SHA-256 and compressed SHA-256. `source-inputs.json` binds complete input directory inventories. Compression is lossless with deterministic gzip timestamps. Raw JSON, stdout, stderr, prompts, source snapshots, failed assertions and owner-stop observations remain byte-exact.

Private operator databases, live journals, signer seeds, provider credentials, private authentication/configuration contents, binaries and package archives are excluded. Public capability descriptors, signatures, request-bound delivery acknowledgements and selected journal-state observations are retained. The latter are observations exported by the test, not a copy of a private journal. Credential scans compare known private values against plaintext and decompressed bytes without printing those values.

`archive-records.py` copies reviewed evidence and refuses changes to an already archived input group. `review-installed.py` performs read-only local post-run comparisons into a new output directory. Neither is needed for offline verification. Archived host and owner drivers are evidence and must not be executed as a verification shortcut.

Run the offline verifier from this directory:

```sh
python3 verify.py
```

The verifier checks all checksums, raw inventory bindings, the successful observations and the retained failures. It does not rerun real hosts or perform a new cryptographic receipt verification. The unchanged product-copy gate and its positive/negative regression suite are recorded separately under the validation raw input group.

Completion still requires the remaining per-host acceptance and usable-delivery work, including unresolved required hosts and release gates. Any changed kernel, plugin, native runtime or enforcement configuration needs applicable fresh real-host runs; these observations do not automatically transfer to a successor artifact.
