# Linux execution profile

The prebuilt applications target Ubuntu 26.04 on x86_64. They use the same native Rust code as the source projects. The generated project README and `release.json` identify the public revision, runtime archive, executable checksums, and locked SDK dependencies.

Install Python 3 and Git. The factory, marketplace, and composed suite also need Bubblewrap. Source builds additionally need Rust 1.94.1, build-essential, pkg-config, libssl-dev, libclang-dev, cmake, and protobuf-compiler.

```sh
sudo apt-get install python3 git bubblewrap
```

Extract a chapter project and run `./run`. The launcher downloads the pinned runtime, verifies the archive and each executable, then opens the native local application. Later launches verify and reuse that runtime. It never downloads or runs a moving branch.

## Marketplace operator

The marketplace requires Linux user namespaces and a delegated cgroup v2 hierarchy with memory and process controllers. On a host with a systemd user session, `./run` opens a delegated scope for this application. It moves only its own process into a leaf, then gives the operator an empty child hierarchy for isolated test processes. Scope setup does not move unrelated host processes or alter their limits.

Install `uv` for the buyer's locked Python environment. The launcher runs `uv sync --locked` against the SDK revision in the project, then uses that environment for proof verification and purchase.

An operator-managed host can instead provide `CHIO_SANDBOX_CGROUP_PARENT` naming an empty delegated cgroup subtree. The operator must have permission to attach its children and enable memory and process limits. A generic container without this delegation is insufficient. The native operator checks its isolation boundary before accepting seller work.

The normal profile mounts private procfs inside the isolated test. A managed execution host may select `CHIO_SANDBOX_PROC=none` when nested private procfs is unavailable. That profile provides no procfs to seller code; it never mounts the host's procfs. The hosted docs use this stricter profile and retain the selected profile in the venue evidence.

## State and shutdown

Run directories contain generated identities, authoritative accounting, private service credentials, and public execution records. Keep the full directory for local recovery; share only the exported run JSON unless you deliberately intend to transfer custody. Ctrl-C stops the web process. An interrupted effect must be reconciled before retrying.

The docs execution host is temporary. Its copied run record is available to the originating browser session for seven days. A factory candidate stays on that host for approximately ten minutes for the publication decision. Download the project for a durable workspace and your own retention policy.
