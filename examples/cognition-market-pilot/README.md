# Cognition Market Coding-Agent Pilot

This example runs a seller agent and buyer agent against one local Chio
operator. The agents receive separate scoped credentials. Neither client file
contains the operator service token.

Build Chio and initialize a private deployment directory:

```bash
cargo build -p chio-cli
target/debug/chio finding operator init \
  --directory "$PWD/.local/cognition-market" \
  --listen 127.0.0.1:7143
target/debug/chio finding operator serve \
  --profile "$PWD/.local/cognition-market/operator-profile.json"
```

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
timer or cron entry.
