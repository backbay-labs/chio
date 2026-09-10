# Capability expiry qualification

This is a shared owner/kernel prerequisite, not six-host acceptance. The owner remains live for host-specific preparation; each host must run its own documented launcher and independently observe the resource.

## Exact identities

- Kernel source `d8c5f53705173e614a853bad6c0a85acfdf1212b`.
- Kernel artifact `/tmp/chio-tool-error-ack-candidate-20260909/chio-33dd1dea21a4`.
- Kernel SHA256 `33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25`.
- Resource image `sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
- Owner `/Users/connor/.local/share/chio-required-operators/capability-expiry-20260909`, endpoint `http://127.0.0.1:58504`.
- Resource volume `chio-required-capability-expiry-20260909`; audit volume has suffix `-audit`.
- Exact launch argument vector is `start-command.json`; policy snapshot is `policy.yaml` and inside the owner directory. No existing owner or volume was reused.

## Measured behavior

The source clamps delegated credential expiry to the earliest retained capability expiry and the requested credential TTL. Therefore a supported delegated credential cannot remain live after this capability expires. This is distinct from a credential-only expiry case on a long-lived capability.

`repro-r2/binding.json` retains the actual issued capability, Ed25519 signature verification against its issuer, matching authenticated context subject/capability ID, and delegated credential public binding. The capability was issued at epoch 1789006884 and expired at 1789006894. Credential TTL 900 was requested but the actual credential expired at 1789006894. Preparation completed with 9.237746953964233 seconds remaining. No clock or database modification was made.

Before expiry, delegated context succeeded and an operator-admission-bearer normal MCP write was allowed. The independent observer saw its exact content. After the actual system time passed expiry+1, the delegated write returned 401; a separate trusted operator admission call using the same retained session returned a signed kernel deny: `capability verification failed: capability has expired`. Both new files were absent. The resource audit contains exactly the one before-expiry write. The trusted operator call is explicitly an inner-kernel check, not a host test.

The initial `probe` preparation succeeded, but the local driver queried the host journal session ID instead of the MCP execution session ID and stopped before any tool call. The corrected driver uses `config.execution.sessionId`. That abandoned private preparation is retained; its capability expired naturally. The full corrected run `repro-r2` passed.

## Fresh host preparation

```sh
python3 /tmp/chio-capability-expiry-20260909/probe.py --prepare-only --name UNIQUE_HOST_NAME
```

The helper uses the installed operator bridge, initializes a new session under the trusted operator, requests a credential TTL 900, confirms that preparation completed while the capability is live, and prints only paths and the expiration timestamp. Private credentials remain under the owner directory. Inspect the emitted binding file, then wait until `time.time() > binding.capability.expires_at + 1` before invoking the host's supported launcher with the emitted gateway configuration. Retain the host launch result and independent volume/audit observations. Do not claim a live real-host action ran if preflight refuses to launch it.

Use unique names; the helper refuses existing output/private preparation directories. `--prepare-only` performs no tools/call. Concurrent names use independent sessions; there are no resource effects. Do not rerun the full probe on this owner because its audit assertion intentionally expects one total dispatch and its filenames identify the original positive control.

No operator token is copied into public evidence. The owner and resource volumes are retained, not removed.
