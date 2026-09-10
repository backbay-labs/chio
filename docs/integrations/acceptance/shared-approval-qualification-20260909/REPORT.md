# Shared operator approval qualification, 2026-09-09

Confidence: high for the bounded effects observed below. This accepts no agent
host. Each of the six required hosts still needs its own I01-I08 evidence using
the final delivered artifacts.

This candidate is rejected for native approval policies with explicit grants.
A follow-up real resource test confirmed that an explicit finite wildcard grant
ignored `require_confirmation: ['*']` and performed an unapproved write.
`initial-native-grant-discovery/` preserves that failure. Fix commit
`6b512c231` applies confirmation and argument-size constraints to explicit
grants and rejects unrepresentable narrow confirmation patterns. Its new native
bounded approval cases require the final aggregate build and rerun. The passing
operator cases below use HushSpec synthesized grants and do not erase this failure.

The real kernel and Docker resource passed `approval-workflow` and
`approved-unknown-after-dispatch` on 2026-09-09 starting at 16:19:33 UTC. The runner
exited zero, recorded no cleanup failure, and verified that the binary did not
change during execution. The documented private operator helper also passed
against a separate real kernel and resource, writing mode-0600 artifacts.

## Exact candidate and final source distinction

- Binary: `/tmp/chio-approval-candidate-20260909/chio`.
- SHA-256: `82e70065d44ce8e09ea1d9c891568eb41bcac6a45ec8d19c0a3480339505cb48`.
- Built base: `b39728c58fc87caabed76f0b2f7f88e863307767`, plus the retained
  `candidate-source/working-tree.patch.gz` (decompress with `gzip -dc`) and new `candidate-source/crates/protocol/chio-mcp-remote/src/remote_mcp/approvals.rs`.
- Decompressed original source patch SHA-256:
  `17cabc4a48c0bfb53e4c30f2a8ab138447a85f41f9acf8728113192af71f3fcc`.
- Final implementation commit: `3ee1169960d5094339f6085ab97ac6bf17537433`.
- Resource image: `sha256:0106edcb15a1c0d12d914ea0504f0e63ec85f5e6fdd3825b4d7a0d1367af3991`.
- Environment: macOS 26.4 build 25E246, Docker 28.3.3.

The binary build completed before a final generated-type compatibility cleanup.
Its generated Rust source had SHA-256
`ae1d3612cfc6a310144ab77eb653116302c86b3f6db96f3ee1047116a34d77c7`.
The final commit's generated Rust has SHA-256
`962a2333b4c01fa42a4fda74817c0f0a58bd3b4015c1297978d6f86cdcffcf2d`.
The cleanup appended and named the wire schema variant to preserve existing
generated SDK type names. It did not change the handwritten approval or kernel
validation code exercised here. These records qualify the exact candidate
above. A final aggregate build and acceptance rerun remain required; do not
silently relabel this binary as built from the final commit.

## Observed behavior

| Case | Independent result |
| --- | --- |
| Pending approval | No file; pending record survives kernel restart. |
| Agent credential against operator endpoint | HTTP 401; no approval issuance. |
| Operator rejection | Signed denied artifact fails normal kernel admission; no file. Rejection cannot later become approval. |
| Changed arguments with valid approval | Kernel rejects the substituted path; neither requested nor substituted file appears. |
| Operator approval | Neither pending nor decision endpoint writes a file. The subsequent ordinary kernel tool call writes the exact approved content. |
| Decision retry | Same decision returns the same artifact; changing the terminal decision returns HTTP 409. |
| Completed approved request after restart | Original signed execution receipt is replayed; independent replacement content remains. |
| Expired pending approval | Decision returns HTTP 409; no file. |
| Modified persistent approval record | Integrity check rejects issuance with HTTP 409; no file. |
| Revocation after approval | Current capability revocation prevents the otherwise approved write. |
| Approved effect with lost reply | The actual resource writes first; its real reply is held before kernel completion. After killing and restarting only the disposable kernel, retry does not overwrite the independent sentinel. |

The last case is an unknown original outcome, despite independently observing a
file in the test. Its retry receipt has signed decision reason `durable admission
failed: request replay is retained in state OutcomeUnknownAfterDispatch` and
outer diagnostic `terminalState: completed`. The signed governed metadata also
records `approval.approved: true`. Approval is permission, and the retry denial
is a decision about redispatch. Neither establishes that the original effect was
denied. Consumers must retain the original unknown outcome.

## Validation and evidence

`cargo check -p chio-mcp-remote` passed. The targeted core test passed 1 case and
the kernel filter passed 4 cases, covering canonical argument equivalence,
argument mutation, capability transfer for the same subject, and validation
ordering. The final Rust/Python/TypeScript/Go generation checks passed. Schema
and generated Python validation passed 3 positive and 8 negative examples.
The two added Rust schema regression tests had not been Cargo-executed when
this candidate record was written; the aggregate verification must run
`cargo test -p chio-spec-validate --test bound_tool_invocation`.

`kernel/` retains the exact runner, policies, raw MCP/admin responses, kernel
logs, independent observations, and response-barrier marker. `operator-helper/`
retains the helper source, raw resource session evidence and recorded helper
results. Private admission/admin credentials and databases are excluded. All
resources were disposable, with separate ports, tokens, databases and Docker
volumes. No shared host-testing kernel was stopped or modified.

Reproduce using the qualified binary and the committed driver:

```sh
python3 integrations/required-agents/qualification/shared_kernel.py \
  --binary /absolute/path/to/chio \
  --source-revision EXACT_SOURCE_IDENTITY \
  --output /tmp/unique-approval-qualification \
  --cases approval-workflow,approved-unknown-after-dispatch
```

See `integrations/required-agents/qualification/APPROVALS.md` for operator
installation, pending/decision, exact-call submission, expiration and recovery.
