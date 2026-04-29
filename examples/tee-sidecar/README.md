# tee-sidecar

Container packaging smoke for `chio-tee`.

This example builds `Dockerfile.tee`, mounts a sidecar TOML file at
`/etc/chio/tee.toml`, and gives the tee a persistent spool volume. It is meant
for operators wiring the TEE sidecar next to an application container, not for
public internet exposure.

## Files

```text
README.md
chio-tee.toml
docker-compose.yml
```

## Run

From this directory:

```bash
docker compose build chio-tee
docker compose run --rm chio-tee --help
```

The runtime image defaults to:

```text
CHIO_TEE_CONFIG=/etc/chio/tee.toml
CHIO_TEE_MODE=verdict-only
```

The compose file overrides `CHIO_TEE_MODE=shadow` so the image exercises the
env layer that takes precedence over the TOML layer. Remove that env entry to
let `[tee] mode = "shadow"` in `chio-tee.toml` provide the same setting.

## Operator Notes

- The config mount is read-only.
- The spool path is a named Docker volume mounted at `/var/lib/chio/tee`.
- The container runs as the non-root `chio` user created by `Dockerfile.tee`.
- The sidecar drops Linux capabilities and sets `no-new-privileges`.
- No host port is published by default.

`chio-tee` is still an M10 phase-1 binary. This example validates the image,
config mount, runtime user, and writable spool shape while later tickets wire
the replay and attestation loop behind the same container contract.
