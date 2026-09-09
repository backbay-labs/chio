# Durable session startup regression

This record qualifies a shared kernel dependency. It does not accept an agent host.

The observed failure is repeated full checkpoint-chain verification while creating
an MCP session: startup reconciles every canonical admission receipt and performs
one separately verified point read per projection. With a modest accumulated
history, synchronous initialization starves other HTTP requests.

The repair adds a bounded lookup of at most 256 receipt IDs. SQLite verifies the
complete checkpoint chain and decodes every requested receipt within one read
transaction snapshot. It starts and verifies a new snapshot for every batch. Missing checkpoint guards
are restored through the single writer; healthy batches use only the reader pool.
There is no cache of verification across calls or sessions. Startup compares each
returned receipt with its canonical admission projection. Missing projections
retain the existing locked point-read and append path, including atomic settlement
observation seeding. Request identity, signed outcomes, startup recovery, ownership
fences, and corruption checks are unchanged.

The optimization applies to the SQLite receipt store used by this integration
qualification. Other receipt-store implementations inherit bounded point reads;
their remote transport performance is not qualified by this record.

## Focused validation

Use the repository's pinned Rust toolchain. The focused commands are:

```sh
cargo test -p chio-store-sqlite --lib receipt_batch -- --nocapture
cargo test -p chio-store-sqlite --lib reader_pool_never_begins_a_write_transaction
cargo test -p chio-kernel --features finding-market --lib
cargo clippy -p chio-store-sqlite -p chio-kernel --all-targets -- -D warnings
cargo build -p chio-cli --bin chio
```

The storage regressions check a full 256-row page performs exactly one full-chain
verification; ordering and misses survive batching; oversized pages fail; a new
batch rejects changed checkpoint, receipt, and unrelated checkpointed claim-log
bytes; and an external write after verification cannot replace the snapshot's
receipt. The existing reader-pool test also executes the new batch with
`PRAGMA query_only = ON`. Kernel tests preserve crash-gap repair, settlement, and
canonical-conflict rejection.

## Real kernel reproduction

`probe.py` starts only the explicitly selected kernel artifacts. It creates a
fresh private state directory and dedicated Docker volume, seeds actual writes
through MCP and the durable kernel using the fixed candidate, and then measures
three new MCP sessions on the baseline and fixed binaries using the same history.
It preserves databases and its resource volume. It never accesses the existing
qualification owner on port 58483. An independent Docker reader checks every file
and its content after restart. The script records artifact and policy digests,
raw tool responses, initialization/context times, checkpoint counts, and effects.
It requires at least one signed checkpoint so an empty-history result cannot pass.
The included test policy permits only filesystem writes, with a finite limit of
256 calls, so the 128-call fixture reaches a checkpoint without changing the
program's host qualification policies.

```sh
python3 probe.py \
  --fixed-kernel /absolute/immutable/fixed-chio \
  --baseline-kernel /absolute/immutable/baseline-chio \
  --policy /absolute/session-startup/policy.yaml \
  --state-dir /absolute/new/private/startup-state \
  --image sha256:0106edcb15a1c0d12d914ea0504f0e63ec85f5e6fdd3825b4d7a0d1367af3991
```

The local Docker image is the qualified official MCP filesystem server described
in `integrations/required-agents/filesystem/`. It is an explicit test dependency,
not a claim of published installation acceptance. The test records time bounds on
this machine; it does not make throughput or scalability claims for untested sizes.

## Recorded results

The combined candidate `d0b87623cb3d...`, source
`25d5717a5bcfd228391dbeee61d8d57f3c5e6177`, passed 764 control-plane,
1,104 kernel, 53 remote-MCP, 112 MCP-edge and 2 schema tests. The focused SQLite
tests and query-only reader regression passed. Clippy passed with warnings
denied across all targets of the five changed library packages.

The real fixture wrote and independently verified 128 files. The baseline
`e7539855906b...` timed out during session initialization at 30 seconds. After
the fixed kernel restarted against that history, its first initialization took
11.92 seconds; subsequent initializations took 1.45 and 1.42 seconds. The first
fixed result exceeded the probe's selected 10-second target, so the original
report correctly retains `passed: false`. A separate authenticated restart
readiness probe took 13.24 seconds, followed by three session initializations
between 1.33 and 1.34 seconds and context queries around 1 millisecond. All prior
effects remained unchanged. These timings are not an all-host overhead gate.

The first harness attempt mishandled an SSE frame before protected work. Its
failure is retained separately. The historical filesystem image in this timing
fixture predates the resource-audit and alias-refusal entrypoint; it qualifies
startup behavior, not the newer resource boundary. Exact raw responses and
measurements are retained in `comparison-v2/` and `restart-readiness.json`.
