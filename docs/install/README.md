# Install Chio

Chio is pre-release and is not yet published to a package registry, GitHub
Release asset set, Homebrew formula, or container registry. Build the CLI from
source for the current checkout:

```bash
git clone https://github.com/backbay-labs/chio.git
cd chio
cargo build --release -p chio-cli
./target/release/chio --help
```

## Release Distribution Contract

The binary, checksum, container, and Homebrew docs describe the release contract
that must be satisfied before those install paths are advertised as available.
They are not current publication evidence.

- Planned binary and image shape: [BINARY_DISTRIBUTION.md](./BINARY_DISTRIBUTION.md)
- Planned Homebrew formula flow: [homebrew.md](./homebrew.md)
- Repo-local Docker demo stack: [../../examples/docker/README.md](../../examples/docker/README.md)
- Proof Room quickstart smoke: [../start-here/PROOF_ROOM_QUICKSTART.md](../start-here/PROOF_ROOM_QUICKSTART.md)

## Next Step

After install, choose the supported path that matches your use case:

1. Guided walkthrough: [../PROGRESSIVE_TUTORIAL.md](../start-here/PROGRESSIVE_TUTORIAL.md)
2. MCP migration and coding agents: [../guides/MIGRATING-FROM-MCP.md](../guides/MIGRATING-FROM-MCP.md)
3. Web backends: [../guides/WEB_BACKEND_QUICKSTART.md](../guides/WEB_BACKEND_QUICKSTART.md)
4. Native Chio servers: [../NATIVE_ADOPTION_GUIDE.md](../start-here/NATIVE_ADOPTION_GUIDE.md)
