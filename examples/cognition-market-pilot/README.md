# Cognition Market Coding-Agent Pilot

This example runs a seller agent and buyer agent against one local Chio
operator. The agents receive separate scoped credentials. Neither client file
contains the operator service token, and the seller credential contains no
market signing key.

Seller packaging requires Git, Bubblewrap (`bwrap`), and util-linux
`prlimit` on the operator host.

Build Chio and initialize a private deployment directory:

```bash
cargo build -p chio-cli
target/debug/chio finding operator init \
  --directory "$PWD/.local/cognition-market" \
  --listen 127.0.0.1:7143 \
  --repository-root /absolute/path/to/repositories
target/debug/chio finding operator serve \
  --profile "$PWD/.local/cognition-market/operator-profile.json"
```

The repository root is the only source tree visible to authenticated seller
submissions. Initialization publishes credentials atomically and is resumable. Repeating
the same command completes or verifies the same deployment without rotating
its identity. A retry with different listen, buyer, seller, or payout values
fails closed. The listen port must be nonzero.

In another terminal, run the seller from the Python SDK environment:

```bash
uv run --project sdks/python/chio-sdk-python \
  examples/cognition-market-pilot/seller_agent.py \
  --credential .local/cognition-market/seller-client.json \
  --repository /absolute/path/to/repository \
  --base BASE_COMMIT \
  --candidate CANDIDATE_COMMIT \
  --test './project-test-command' \
  --topic coding/verified-fix
```

Use the returned `findingId` with the buyer:

```bash
uv run --project sdks/python/chio-sdk-python \
  examples/cognition-market-pilot/buyer_agent.py \
  --credential .local/cognition-market/buyer-client.json \
  --chio target/debug/chio \
  --finding FINDING_ID \
  --patch /tmp/verified-fix.patch
```

The buyer verifies the proof with the Rust reference verifier before purchase
and writes the revealed patch to the requested path. It never changes a source
workspace. Review the patch, prepare a disposable sandbox, and apply it as a
separate action:

```bash
git clone /absolute/path/to/repository /tmp/fix-sandbox
git -C /tmp/fix-sandbox checkout BASE_COMMIT
git -C /tmp/fix-sandbox apply --check /tmp/verified-fix.patch
git -C /tmp/fix-sandbox apply /tmp/verified-fix.patch
```

`chio finding operator tick` reports retained bundles, purchase jobs,
terminals, and captures. It is idempotent and suitable for a local service
timer or cron entry. The operator accepts at most 10,000 durable purchase jobs;
at capacity, new purchases fail closed while exact retries remain replayable.
Live seller admission and `operator tick` share one cross-process admission
lock. Only one seller submission or retraction enters blocking execution at a
time; overlapping requests receive HTTP 503 and can retry the same durable
identity. A prepared purchase ask is checked against current operator time
before its first reservation. An expired ask cannot reserve funds, and the
buyer must prepare a fresh purchase request.

The Python and TypeScript buyer SDKs verify status proofs with the profile's
pinned status authority, service bond, freshness window, and a durable rollback
floor. Evidence-invalid challenge helpers accept only a purchased verified-fix
result and authenticate its purchase terminal again before filing. Seller
prices are capped at 450 units, matching the operator's maximum backed sale
exposure.

## System service repository boundary

The included systemd unit keeps operator state writable only under
`/var/lib/chio/cognition-market` and exposes seller source repositories
read-only under `/srv/chio/cognition-market-repositories`. Prepare both roots
before starting the service:

```bash
sudo install -d -o chio -g chio -m 0700 /var/lib/chio/cognition-market
sudo install -d -o root -g chio -m 0750 /srv/chio/cognition-market-repositories
sudo git clone /absolute/path/to/repository \
  /srv/chio/cognition-market-repositories/project
```

Pass the staged `/srv/chio/cognition-market-repositories/project` path as
`--repository`, and configure `/srv/chio/cognition-market-repositories` as the
`operator init --repository-root`. Operator ingress canonicalizes each submitted
path and rejects anything outside that root. Packaging first clones its objects without hard links into the
operator-owned packages directory, with repository hooks and external Git
helpers disabled. It creates self-contained baseline and candidate clones so
Git-based build tooling remains available without mounting shared repository
metadata. Each test receives a private size-capped tmpfs, no network, a
five-minute deadline, a cleared environment, bounded output, hard memory, CPU,
process, descriptor, and file-size limits, and no mount of the operator profile
or state directory. Repository clone and checkout staging also has a
five-minute deadline, a 1 GiB aggregate storage ceiling, a 75,000-entry
ceiling, and a per-file size limit. Published repository identity strips URL
credentials, query strings, and fragments.

The sandbox mounts toolchain executables but not the operator account's Cargo
registry or Git dependency caches. Rust repositories that need third-party
dependencies must commit a vendored source tree and its offline Cargo
configuration. The operator retains at most 256 seller submission and
retraction jobs combined, and reserves the full transient staging budget plus
publication headroom within an 8 GiB and 100,000-entry package/report storage
ceiling.
