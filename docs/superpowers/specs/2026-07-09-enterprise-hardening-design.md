# Design: enterprise hardening pack

- Status: REVISED, implementation contract
- Date: 2026-07-09
- Revised: 2026-07-10
- Scope: `chio-keyring`, `chio-secret-broker`, `chio-cage`, and the manifest and runtime integration required to make them enforceable
- Related normative docs: `spec/PROTOCOL.md`, `spec/SECURITY.md`, `docs/security/threat-coverage.md`
- Sibling designs: `2026-07-09-security-folder-design.md` and `2026-07-09-protocol-primitives-design.md`

## 1. Decision

This arc adds three security boundaries, but it does not invent parallel versions of primitives Chio already has.

1. `chio-keyring` extends the RFC 6962 Merkle implementation in `crates/core/chio-core-types/src/merkle.rs` with append-only consistency proofs. It stores immutable key-lifecycle events, publishes signed checkpoints, and requires independent witness signatures before a checkpoint is trusted.
2. `chio-secret-broker` is a separate, trusted process that executes authorized downstream requests. It never returns credential bytes to an agent or tool server. The broker is part of the trusted computing base because it can read and use credentials and because it enforces their destination and request constraints.
3. `chio-cage` admits only a verified `chio_manifest::SignedManifest`, retains validated resources as FDs, and sends a sealed plan to a fresh trusted `chio-cage-init` process. Cage-init applies nono Landlock and a separate default-deny seccomp filter, then executes the retained target FD.

The former design's rolling hash was not a Merkle transparency log, its broker API returned raw secrets, and its cage backend returned success without applying confinement. None of those approaches may be retained as a compatibility path.

## 2. Goals

- Rotate authority signing keys transactionally, with an explicit overlap window and no interval in which zero or multiple keys can sign new artifacts.
- Let verifiers prove that a signing key is present in a specific log checkpoint and that a later checkpoint is an append-only extension of an earlier checkpoint.
- Detect split views through independently operated witnesses and checkpoint gossip.
- Keep long-lived credential material inside the broker process for its entire lifetime.
- Bind each broker execution to the calling Chio capability, subject, credential reference, provider, exact destination, request shape, proof-of-possession key, expiry, revocation state, and an atomically enforced execution limit.
- Launch native tool servers only after manifest authentication, permission validation, filesystem and network restriction, syscall restriction, file-descriptor closure, and environment construction have all succeeded.
- Emit receipts that state what the operating system actually enforced, not what configuration requested.
- Supply adversarial and integration evidence suitable for the threat-coverage process. A mechanism does not close a threat row by itself.

## 3. Non-goals

- This arc does not implement HSM, KMS, or Vault drivers. Deployments that require those systems need separately reviewed drivers; v1 still ships the production encrypted-SQLite secret backend defined below.
- This arc does not send credentials to a tool through environment variables, files, command-line arguments, IPC responses, logs, or receipts.
- This arc does not claim hostname allowlisting from Landlock. Linux Landlock network rules are port-oriented. Host and IP destination enforcement stays in the broker or an authenticated egress proxy.
- This arc does not treat `nono` seccomp user notification for `openat` and `openat2` as a general syscall allowlist. `chio-cage` installs a separate seccomp-BPF allowlist.
- This arc does not silently launch unconfined on unsupported kernels. Unsupported enforcement is an admission denial.
- Windows native sandboxing is out of v1. macOS support may be added after the Linux contract is complete, but must have platform-specific behavioral evidence and truthful enforcement reporting.

## 4. Existing Chio surfaces

The implementation must build on these existing APIs:

- Canonical signed data uses `chio_core_types::canonical::canonical_json_bytes` and the `Keypair::sign_canonical` or `SigningBackend` paths in `chio-core-types`.
- RFC 6962 leaf hashing, node hashing, trees, and inclusion proofs live in `crates/core/chio-core-types/src/merkle.rs`. Consistency proofs must be added there rather than in `chio-keyring`.
- The cage consumes the full `chio_manifest::SignedManifest` from `crates/platform/chio-manifest`. It calls `verify_manifest` with the registered server key and then validates and normalizes `required_permissions`.
- The active-defense arc makes `chio_core_types::manifest::ToolDefinition` the sole normative tool-definition shape and makes `chio-manifest` reexport it while retaining the full signed platform manifest. Enterprise manifest work must land after active-defense Phase 2 or in the same coordinated PR. The two arcs must not edit divergent `ToolDefinition` shapes.
- `chio_core_types::manifest::ToolManifest` remains a different, older signed representation, but it is platform-incomplete: it lacks the platform `RequiredPermissions` contract and its self-verification does not perform registered-key admission. It is not an acceptable cage envelope. Reusing the normative core `ToolDefinition` does not change that boundary.
- Chio already has DPoP and revocation machinery. Broker proof binding and capability liveness should reuse those semantics and low-level types without creating a dependency from a core crate back into the kernel.

## 5. Threat model

| Adversary | Capability | Required result |
|---|---|---|
| Compromised agent | Can call broker and tool APIs with attacker-selected inputs | Cannot obtain credential bytes or execute outside the signed broker capability |
| Compromised tool server | Controls its process after launch | Remains inside the enforced filesystem, network, syscall, FD, and environment boundary |
| Malicious manifest publisher | Signs broad, malformed, or ambiguous permissions | Permission validation rejects ambiguity; operator policy may narrow but never widen the signed request |
| Compromised broker client | Replays or races requests | Proof nonce and execution reservation are atomic; limits cannot be overspent |
| Compromised credential provider | Returns malformed secret material | Broker fails closed, zeroizes material, and never serializes it across IPC |
| Compromised key-log operator | Omits, reorders, rewrites, or equivocates | Inclusion, consistency, checkpoint-chain, witness, and gossip verification detects the violation |
| Compromised current authority key | Attempts a hidden or unilateral rotation | Normal rotation requires old-key and new-key signatures plus a committed event; emergency recovery is separately authorized and visible |
| Local unprivileged attacker | Manipulates symlinks, inherited FDs, environment, DNS, or process startup | Validation and child bootstrap reject the launch or request before privileged execution |

Out of scope adversaries are a compromised host kernel and physical extraction of backend-held key or credential material. Those require hardware and host integrity controls outside this arc.

## 6. Cross-cutting invariants

1. Every security decision is fail-closed. Serialization errors, storage errors, clock errors, unavailable revocation state, unsupported enforcement, and incomplete child bootstrap deny the operation.
2. Every signed artifact has a versioned schema and explicit domain. Signatures cover RFC 8785 canonical JSON, never an ad hoc concatenated string.
3. Durable state changes use a transaction or compare-and-swap. A rotation proposal may be visibly pending, but active-key selection changes only in the witnessed activation transaction. Broker execution limits use the protocol's authoritative `BudgetStore` hold and event model rather than a broker-owned counter.
4. Secret-bearing types do not implement `Serialize`, `Clone`, or `Debug`; use zeroizing byte storage and redacted errors.
5. Receipts contain hashes, identifiers, policy versions, and enforcement facts, never private key material, credentials, proof secrets, or unredacted authorization headers.
6. A local configuration can narrow signed authority but cannot widen it.
7. Wall-clock expiry is checked against a bounded-skew clock source. Sequence numbers, nonces, and durable state prevent rollback and replay even when clocks move backward.

## 7. `chio-keyring`

### 7.1 Trust boundary

`chio-keyring` is authority-adjacent and part of the authority's TCB. The log operator signs checkpoints but does not hold authority private keys. Witnesses are independently configured trust roots. A verifier trusts a checkpoint only when it has a valid operator signature and the configured witness threshold.

Private signing operations remain behind `SigningBackend`. The key log contains public keys and lifecycle events only.

### 7.2 Immutable event model

`KeyLogEventBody` is unsigned and contains:

- `schema`, `log_id`, `sequence`, `event_id`, and `previous_event_hash`
- `authority_id`, `key_id`, `algorithm`, and self-describing `public_key`
- one operation: `genesis`, `rotate`, `abort_rotation`, `retire`, or `revoke`
- `effective_at`, optional `verify_until`, `reason`, and `issued_at`
- for rotation, `previous_key_id` and the configured witness-roster identifier
- for emergency recovery, an explicit recovery-policy identifier

Every event authorization signs the same domain-separated canonical bytes of this unsigned body. A normal rotation has an old-key authorization and a new-key proof-of-possession authorization. Recovery has distinct recovery-authorizer signatures satisfying the configured threshold. `SignedKeyLogEvent` is the envelope containing the body and its typed authorization signatures. Signatures never cover an object that contains those same signatures.

The Merkle leaf bytes are canonical JSON for the complete `SignedKeyLogEvent` envelope, including the authorization signatures. `previous_event_hash` is the domain-separated hash of the previous complete envelope. The sequence equals the zero-based leaf index. This removes self-reference while committing the log to every authorization byte.

The verifier derives state by replaying immutable envelopes. Existing leaves are never rewritten to change a key's status. It rejects duplicate sequences, event IDs, or key IDs; sequence gaps; invalid predecessor hashes; invalid event signatures; unsupported algorithms; algorithm and public-key mismatches; invalid time ordering; concurrent pending rotations; multiple active signing keys; and retirement or revocation of an unknown key.

### 7.3 Witnessed two-stage rotation

Normal rotation has two durable stages:

1. In a transaction, validate and append the dual-signed rotation envelope and publish an operator-signed pending checkpoint containing it. The old key remains the only signing key. The new `SigningBackend` handle is staged and unavailable to every artifact-signing route.
2. Witnesses verify the pending checkpoint and return signatures. Once a strict-majority threshold is present, an activation transaction verifies the exact event, checkpoint, roster, and witness signatures, stores the witnessed checkpoint, records activation from that witnessed checkpoint rather than a proposal-supplied time, increments the signing epoch, and changes the active-key selector to the new backend. Only that commit exposes the new backend to signing.

Artifact code never receives a free `SigningBackend` handle. It calls a `KeyringSigningRouter` that serializes each signature against activation under the authoritative selector. A signing operation acquires the current `(key_id, signing_epoch)` fence, holds its shared signing lease through backend completion and durable artifact-hash anchoring, and returns the epoch in signed evidence. Activation takes the exclusive selector lease, waits for earlier signing operations to finish, commits the new epoch and key, closes the old route, and only then admits new signing. A stale worker, stale lease, or old backend handle cannot publish an artifact under the new epoch. Multi-worker deployments require one shared linearizable selector and fenced lease service; a local-only selector is restricted to one signing process.

A crash or storage failure before activation leaves the old key active and the proposal pending. Retrying witness collection and activation is idempotent. Recovery reconstructs the selector epoch before any artifact-signing route opens. An operator may append a dual-authorized `abort_rotation` event while the old key remains available. If the old key is unavailable, only the explicit threshold recovery policy may abort or supersede the proposal. The log never silently skips or deletes a pending rotation.

Verifiers apply a rotation state transition only when the checkpoint containing the rotation has the required witness threshold. The overlap window permits verification of already anchored old-key artifacts, not new signing with the old key. Revocation is distinct from expiry and may invalidate a former overlap window according to the configured revocation policy.

### 7.4 Merkle, synchronization, and checkpoint contract

`chio-core-types::merkle` is extended with:

- an append-oriented tree or frontier that produces the same roots as the existing RFC 6962 tree
- `ConsistencyProof { old_size, new_size, audit_path }`
- proof generation and verification against both the old and new roots
- cross-check tests against the existing tree and fixed RFC 6962 vectors

`chio-keyring` adds key-log leaf encoding and these artifacts:

```text
KeyLogCheckpointBody {
  schema, log_id, checkpoint_sequence,
  tree_size, root_hash, previous_checkpoint_hash,
  issued_at
}

SignedKeyLogCheckpoint {
  body, operator_key_id, operator_algorithm, operator_signature,
  witness_signatures[]
}
```

The operator and every witness sign a domain-separated canonical checkpoint body. A synchronization response carries every checkpoint envelope in `(A.checkpoint_sequence, B.checkpoint_sequence]`, every leaf in `[A.tree_size, B.tree_size)`, and the required consistency proofs. A client updating from checkpoint A to B verifies:

1. schemas, log ID, monotonic checkpoint sequence, tree size, and issuance time;
2. every intermediate checkpoint's operator signature, strict-majority witness threshold where activation is claimed, exact sequence, and predecessor hash;
3. an RFC 6962 consistency proof from A to B when the tree grew;
4. every contiguous complete event envelope in leaf range `[A.tree_size, B.tree_size)`, checking leaf index against event sequence, predecessor hash, event signatures, and canonical leaf hash;
5. the new root rebuilt from the locally retained leaves or frontier plus every received envelope, and equality with B's root;
6. full key state replay through B, including witnessed rotation activation, before trusting any key.

A consistency proof proves append-only root evolution but does not supply the state-changing leaves. An inclusion proof for one key proves only membership and is insufficient to prove that no later event retired, revoked, or superseded it. A new verifier must download the complete log and checkpoint history from genesis and rebuild the checkpoint roots, witnessed activation history, and state. A compact snapshot is acceptable only after an authenticated state-proof design lands; v1 does not define one.

### 7.5 Witness service and artifact-time verification

Each witness is a stateful service with a durable pinned head. Before signing a candidate it verifies the operator signature, checkpoint sequence and predecessor, consistency proof from its pin, every contiguous new envelope, rebuilt root, event authorizations, and full replayed key state. In one durable transaction it records the candidate decision and advances its pin before returning its signature. It refuses a different root for any previously observed or signed `(log_id, checkpoint_sequence)` or `(log_id, tree_size)` pair and gossips the conflict evidence.

For a fixed roster of `n` independent witnesses, acceptance requires `floor(n / 2) + 1` signatures, which is strictly greater than `n / 2`. This quorum-intersection rule is required in addition to gossip and each witness's no-conflict invariant. Roster changes require a separately witnessed configuration event and are not part of v1 rotation.

Key validity at artifact time requires trusted time evidence. An artifact's self-asserted `signed_at` is insufficient because an old key can backdate it after rotation. Verification of an old-key artifact requires an inclusion proof in a Chio receipt checkpoint or another configured trusted timestamp anchor committed before witnessed rotation activation, plus an artifact hash binding. The artifact must also fall inside the key's verification policy and must not be invalidated by revocation. A new-key artifact anchored before witnessed activation is rejected.

A failed update never replaces the last accepted checkpoint. Witnesses gossip signed checkpoint hashes. Two valid checkpoints for the same log, sequence, or tree size with different roots are durable equivocation evidence.

## 8. `chio-secret-broker`

### 8.1 Trust boundary and process model

The broker is in the TCB. It can read credentials and can make authenticated downstream requests. Compromise can disclose credentials or misuse them within reachable infrastructure, so process isolation, egress control, audit, and backend hardening are mandatory.

Agents and tool servers communicate with the broker over authenticated local IPC or mTLS. They receive an opaque signed execution capability. They submit an uncredentialed request. The broker validates the capability, injects the credential internally, executes the downstream request, strips credential-bearing response metadata, and returns the sanitized response.

There is no public `resolve`, `get_secret`, or equivalent API returning a `String`, byte vector, file path, or environment variable. `SecretBackend::materialize` is service-private and returns a zeroizing, non-serializable value usable only by provider code in the broker process.

### 8.2 Production secret storage and provisioning

V1 ships `EncryptedBlobSecretBackend` as a production backend. It uses `chio_store_sqlite::SqliteEncryptedBlobStore`, `TenantId`, `TenantKey`, and opaque `BlobHandle` values. A broker-owned metadata table maps a tenant-scoped, versioned `CredentialRef` to a blob handle. Decrypted bytes move immediately into `SecretMaterial` and are zeroized after provider use.

Provisioning is an authenticated broker administration operation, authorized by an operator capability or configured governed approval. The broker accepts credential bytes, writes the encrypted blob and reference mapping transactionally, emits a redacted receipt, and never returns the credential. Reads, writes, version changes, disablement, and deletion are tenant-scoped and audited.

The `TenantKey` master material is delivered at process creation through a sealed, read-only inherited file descriptor or through a reviewed custody-provider API. Environment variables, command-line arguments, ordinary files, and compiled constants are prohibited key transports. The broker validates FD seals, exact key length, ownership, and single-read semantics before serving. Missing or invalid custody blocks startup. Vault and HSM backend drivers remain non-goals, but an encrypted SQLite production backend does not.

### 8.3 Signed execution capability

`BrokerCapabilityBody` binds all of the following:

- schema, issuer, capability ID, parent Chio capability ID, subject, audience, issued-at, not-before, and expiry
- `CredentialRef { provider, credential_id, version }`
- provider adapter identifier and version
- `Destination { scheme, normalized_host, explicit_port, exact_path_and_query, method }`
- allowed caller-supplied header names and an explicit list of headers the provider injects
- maximum body bytes, required body SHA-256, and whether an approved preview hash is required
- redirects disabled in v1, response-size limit, and streaming permission
- a distinct broker-capability quota key, maximum executions, attempt-consumption semantics, and revocation handle
- `ProofBinding { mode, caller_public_key, nonce_ttl }`

The issuer signs the body with Chio canonical JSON and Chio signing types. Provider, key algorithm, and public key must agree. Unknown fields and schema versions are rejected.

The request proof signs a canonical, domain-separated body containing the broker capability ID, request method, normalized destination, body hash, a canonical digest of every normalized caller-controlled header name and value, a canonical digest of every caller-controlled execution option, nonce, and issuance time. Header and option digests use closed schemas, deterministic ordering, and duplicate rejection so no request behavior remains outside the proof. Nonces are stored atomically and cannot be replayed. A loopback bearer secret is allowed only in explicit development configuration and is not a production proof mode.

The enterprise crate implements the kernel-owned `SupplementalQuotaVerifier` port. Runtime composition installs that trusted adapter; the kernel passes opaque broker-capability bytes plus its own capability, subject, request, destination, and arguments context. The adapter performs the same signature, issuer, parent, subject, destination, constraint, expiry, and revocation-identifier validation and returns a request-bound supplemental quota claim. Neither the wire request nor `chio-secret-broker` constructs a kernel budget key directly, and `chio-kernel` does not depend on the enterprise crate.

### 8.4 Execution sequence

For each request the broker performs, in order:

1. Decode with size limits and reject unknown fields.
2. Verify issuer, signature, audience, time bounds, proof binding, nonce shape and freshness, subject, parent Chio capability liveness, and broker-capability revocation without consuming the nonce yet.
3. Parse and normalize the URL once. Require HTTPS except explicit loopback tests. Match scheme, host, effective port, method, and exact path plus query.
4. Reject IP literals and DNS results in loopback, private, link-local, multicast, documentation, carrier-grade NAT, and other configured restricted ranges unless an explicit signed policy allows the exact target. Pin the validated address for connection to prevent DNS rebinding.
5. Reject caller injection of `Authorization`, `Proxy-Authorization`, `Cookie`, `Host`, hop-by-hop headers, provider-owned headers, and any header absent from the signed allowlist. Normalize all remaining caller headers and options and verify their canonical digests against the request proof.
6. Recompute the request body hash over bytes and compare it with the capability and approved preview. Do not trust a caller-supplied hash.
7. During authenticated local `RegisterAttempt`, before the coordinator makes any remote budget call, atomically consume the proof nonce and persist and fsync a deterministic pending attempt intent containing operation and attempt ids, canonical request digest, broker capability ID, invocation ID, quota-key set, hold ID, and event IDs. Return an idempotent acknowledgement without materializing a credential. Retries and startup recovery query authoritative state by those ids. An unknown result remains pending and denies dispatch.
8. Only after registration acknowledgement, ask the injected `BrokerExecutionBudget` port for one atomic hold over the existing per-grant quota, the optional parent aggregate quota, and the distinct broker-capability quota. All keys are deduplicated. A brokered logical invocation uses one hold ID end to end; it never charges the parent aggregate in both the kernel and broker.
9. After the coordinator reaches `ReadyToDispatch`, check revocation again, materialize credential bytes inside the broker, and let the provider adapter prepare the credentialed request without sending it. A denial or preparation failure before dispatch reverses the hold with an idempotent event only when the broker can prove dispatch did not begin.
10. With the protocol operation in `CapturePending`, call `AdmissionCaptureAuthority` with the hold, operation, the operation-bound canonical revocation set and digest, and verified broker authorization-artifact digest. The set contains the leaf parent capability, every verified delegation ancestor, and the broker capability's revocation ids. The authority serializes relevant revocation writes and invocation capture in one commit, denies any revoked or mismatched member, captures every quota exactly once, and returns combined budget and revocation commit metadata. The coordinator then persists `DispatchCommitted`; only that state permits the network send. After capture, the execution remains consumed even if the process crashes before send, the upstream times out, or the response is lost.
11. Execute with redirects disabled, zeroize temporary buffers, sanitize the response, reconcile the pending intent to the authoritative hold and capture or reversal result, commit signed evidence, and return only the sanitized response and receipt reference.

Provider adapters own credential placement. The generic HTTPS provider must support only reviewed injection schemes, validate TLS, cap request and response sizes, and never forward caller authorization headers. Secret scanning is a defense-in-depth output check, not the mechanism that keeps credentials out of another process.

`BrokerExecutionBudget` is an injected authorization port, not a second budget implementation. Its operations correspond to authoritative hold, query, reverse, and combined capture events. The protocol budget key model gains a domain-separated `broker_capability` dimension keyed by the verified broker capability ID. That quota supplements the parent aggregate quota when present; the two constraints remain distinct members of one hold. Combined capture must use a single SQLite transaction or consensus log that also owns relevant revocation writes; a sequential revocation read plus budget capture is not acceptable. Until the protocol arc supplies atomic multi-key holds, the supplemental-verifier port, authoritative event semantics, and combined capture, production broker execution is unavailable and fails closed. Unit tests may use an in-memory implementation of the same port and combined authority.

Broker-local attempt rows are a durable write-ahead intent and reconciliation journal. They contain deterministic IDs and references to authoritative results but do not determine remaining uses. A crash after a remote commit cannot create an orphan: restart queries by operation, hold, and event ID and applies the returned authoritative result idempotently. Recovery never sends a captured request unless `DispatchCommitted` is durable and the upstream protocol proves the same operation id is idempotent; otherwise it records an unknown outcome. An unreachable or ambiguous authority leaves the intent pending and blocks retry side effects.

## 9. `chio-cage`

### 9.1 Admission and permission model

The cage accepts only `chio_manifest::SignedManifest` plus the registered public key and local operator ceilings. It calls `verify_manifest`, which also validates the manifest and embedded signer binding. It hashes the verified canonical manifest and carries that digest through compilation, launch, and receipt emission.

The current `RequiredPermissions` fields are strings. Cage validation converts them into typed `ValidatedPermissions` before any process creation:

- paths must be absolute, normalized, duplicate-free, and free of NULs and traversal;
- existing paths are resolved once and retained as `O_PATH | O_CLOEXEC` descriptors; device, inode, mode, mount identity, and expected access are recorded;
- a missing writable file is securely precreated beneath a retained parent directory FD with `openat2` resolution constraints, exclusive creation, no symlink following, explicit mode and ownership, and then retained by `O_PATH`; otherwise the missing target is rejected;
- missing directories, wildcard future children, and path grants that require reopening by name are rejected in v1;
- read and write modes remain distinct, and root-level grants are rejected by default;
- network entries parse into normalized host and explicit port records;
- environment entries are names only, validated against a strict syntax;
- native launch requires an explicit versioned syscall profile. An absent or unknown profile denies launch.

These signed permission changes are mandatory inputs to the strict `chio.manifest.v2` migration coordinated with active-defense Phase 2. Neither arc may freeze or ship v2 without the unified `ToolDefinition`, strict nested parsing, flow declarations, typed cage permissions, and syscall profile. V1 signed bytes are never reinterpreted, and cage denies v1.

Operator policy may remove permissions, lower limits, or deny launch. It cannot add paths, destinations, environment names, or syscalls absent from the verified manifest.

### 9.2 Profile compilation

Compilation starts from deny-all. This is important because `nono::CapabilitySet::new()` currently defaults network access to `AllowAll`.

- Add only validated filesystem grants by retained descriptor. Resolve forbidden paths before grants because Landlock cannot subtract a path after it is allowed. Patch the pinned nono API to add Landlock rules from caller-owned FDs rather than reopening paths.
- Set network to `Blocked` explicitly. A brokered tool receives one already-connected, authenticated Unix-domain IPC FD; its seccomp profile denies `socket`, `connect`, and `bind`, so it needs no Landlock network grant. A loopback TCP port is not an endpoint identity because Landlock permits by port rather than host. Direct egress likewise uses a preconnected or descriptor-passed authenticated proxy channel unless a stronger network namespace and destination-enforcement design is separately approved.
- Construct a minimal environment from fixed runtime keys and the manifest's allowed variable names. Do not inherit the parent environment. Deny credential-like variables and dynamic-loader injection variables such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, and platform equivalents.
- Open the target executable and required runtime files before sandboxing and retain their FDs. System resources are explicit compiler inputs, included in the profile hash, and never inferred as broad `/usr` or `/` grants.
- Select a reviewed, versioned, architecture-specific syscall allowlist. Install it with a default-deny seccomp-BPF filter. `nono` seccomp notification is not used as this filter.

The result is a deterministic `CompiledSandboxProfile` containing the manifest digest, compiler version, normalized FD-slot grants and identities, nono capability digest, seccomp profile digest, helper identity, target identity, environment-name set, and required enforcement levels.

### 9.3 Dedicated cage-init launch protocol

The multithreaded runtime never calls nono, Landlock, seccomp, or custom post-fork hooks. It launches a dedicated trusted `chio-cage-init` executable as a fresh process through the platform's normal spawn path. Cage-init has no async runtime, starts single-threaded, applies confinement to itself, and then replaces itself with the target.

Before sending a launch plan or privileged FDs, the parent verifies the running helper's `/proc/<pid>/exe` device, inode, and content digest against the pinned helper identity. The canonical launch plan is placed in a sealed read-only memfd. Retained `O_PATH` resource and target FDs are passed in fixed numbered slots. The helper revalidates the plan signature or parent-authentication tag, seals, FD count, every `fstat` identity, manifest and profile hashes, its own identity, and the target identity. V1 rejects set-user-ID, set-group-ID, file-capability, and other privilege-changing targets.

Linux launch uses a kernel-observed exec transition, not status-pipe EOF as proof. After input verification and before confinement, the single-threaded helper calls `PTRACE_TRACEME` and stops. The trusted parent sets `PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL` and continues it. A successful `execveat` generates `PTRACE_EVENT_EXEC` before target code resumes, allowing the parent to verify the live `/proc/<pid>/exe` identity against the retained target FD, record `ExecTransitionObserved`, and detach. If this trace contract is unavailable or policy forbids it, v1 launch is `Unsupported` and denies.

Cage-init then:

1. confirms it is single-threaded, establishes the parent trace handshake, and closes every descriptor except standard streams, the sealed plan, retained resource and target FDs, the child write end of the status pipe, and explicitly declared IPC descriptors;
2. sets `no_new_privs`, resource limits, signal state, working-directory FD, user/group policy where configured, and the minimal prebuilt environment;
3. adds Landlock rules from retained FDs through the patched nono API and applies the ruleset, rejecting `PartiallyEnforced` and `NotEnforced`;
4. installs and verifies the independent seccomp-BPF filter, including only the reviewed `execveat` or `fexecve` transition;
5. writes `EnforcementPrepared` with manifest, profile, helper, target, FD-table, Landlock, seccomp, and trace-session digests to a status descriptor marked `CLOEXEC`;
6. executes the already-open target FD with `execveat(..., AT_EMPTY_PATH)` or an equivalent `fexecve`, without resolving its pathname again. V1 rejects script targets that would force the kernel to reopen an interpreter path; a reviewed interpreter must instead be the target with the script supplied through an explicit retained FD.

Every helper error path writes a structured failure record and exits without closing the status descriptor as success. Successful target exec closes the descriptor in the kernel because of `CLOEXEC`, but EOF is corroborating cleanup evidence only. Helper death and `SIGKILL` also close the descriptor and therefore cannot establish exec.

The parent requires exactly one matching `EnforcementPrepared` record, one matching kernel `PTRACE_EVENT_EXEC`, verified post-exec target identity while the tracee is stopped, and status-pipe EOF under a deadline. It records `FullyEnforced` before detaching and resuming target code. An immediately exiting target still produces the exec event first, then `Exited`. Prepared plus EOF without the exec event, tracee death, a structured failure, extra bytes, non-EOF, malformed data, identity mismatch, or timeout is `BootstrapFailed`. The parent terminates and reaps any remaining process on failure and supervises the target on success.

### 9.4 Truthful enforcement states

Configuration intent and observed enforcement are separate:

- `Unsupported`: the platform or kernel cannot provide a required mechanism.
- `Rejected`: manifest or operator policy validation failed before launch.
- `BootstrapFailed`: the child did not complete confinement and exec.
- `FullyEnforced`: required Landlock and seccomp mechanisms reported full enforcement, the parent received matching prepared evidence, the kernel reported `PTRACE_EVENT_EXEC`, the stopped post-exec image matched the retained target identity, and CLOEXEC EOF corroborated descriptor closure. Target liveness after the exec event is not required.
- `Exited`: a previously fully enforced process terminated, with exit or signal status.

There is no production `BestEffort`, `Partial`, or `Unconfined` success state. Diagnostic commands may report those observations but cannot launch the tool.

## 10. Crate and dependency boundaries

| Crate | Responsibilities | Must not do | TCB |
|---|---|---|---|
| `chio-core-types` | Existing RFC 6962 primitives plus generic consistency proof types and verification | Know about keys, brokers, or processes | Core cryptographic TCB |
| `chio-keyring` | Key events, transactional state derivation, checkpoints, witnesses, verifier | Store authority private keys or implement a second Merkle tree | Authority TCB |
| `chio-secret-broker` | Signed broker protocol, broker service, provider adapters, execution store, sanitized receipts | Expose raw credential-returning APIs | Credential and egress TCB |
| `chio-cage` | Manifest admission, FD-based permissions, profile compilation, cage-init protocol, enforcement evidence | Accept incomplete admission or reopen validated resources by path | Native launch TCB |
| `chio-manifest` | Signed manifest schema and structural validation | Apply OS policy | Admission TCB |
| Runtime composition layer | Connect trusted keys, revocation, receipt sink, broker, and cage | Introduce reverse dependencies into core crates | Kernel-adjacent TCB |

Dependencies point from the new security crates into core and platform primitives, not from `chio-core-types` into security crates. Runtime wiring belongs in the existing composition layer, not inside a low-level crypto or manifest crate.

### 10.1 Signed and wire schemas

Enterprise artifacts are public protocol surfaces, not Rust-only structs. JSON Schemas live under `spec/schemas/chio-wire/v1/security/` for key-log event envelopes, checkpoints, witness signatures, log synchronization, broker capabilities, request proofs, execution requests and evidence, cage launch plans, prepared records, exec-transition observations, enforcement records, and enterprise receipts. Every signed schema separates its unsigned body from its signature envelope and closes unknown fields.

Every schema is registered in `spec/schemas/registry.json`, hashed in `spec/schemas/MANIFEST.sha256`, documented in the chio-wire README, and covered by `scripts/check-chio-schema-registry.sh`. The four-language `cargo xtask codegen` output and `make codegen-check` must include the new security directory. Canonical positive and negative vectors live under `tests/bindings/vectors/security/` and update that tree's `MANIFEST.sha256`.

`crates/tooling/chio-conformance` adds native scenarios for signature separation, key-log contiguous synchronization, witness conflict refusal, broker proof binding and quota behavior, encrypted credential handling, cage-plan identity, and enforcement evidence. `.github/workflows/enterprise-hardening.yml` runs portable schema, codegen, and conformance jobs plus a non-optional `linux-enforcement` job with `runs-on: [self-hosted, linux, x64, chio-enterprise-security]`. That runner label contract includes the documented Landlock ABI, seccomp, `openat2`, `execveat`, O_PATH, memfd seals, and parent-child `PTRACE_EVENT_EXEC` requirements. Release evidence is invalid until that actual runner job passes.

## 11. Receipts and audit evidence

All receipts are canonical and signed through existing Chio receipt infrastructure.

- Key receipts identify complete-envelope hash, event, pending or active stage, tree size, root, checkpoint hash, signer IDs, witness roster and signatures, transaction ID, and outcome.
- Broker receipts identify broker capability, parent capability, subject, credential reference hash and version, normalized destination, body, header, and option digests, every quota key, complete checked revocation-set digest, hold and event IDs, combined budget and revocation commit indices and leader epoch, provider, response status, byte counts, and outcome. They exclude credentials and sensitive header values.
- Cage receipts identify manifest, plan, FD table, helper, target, and profile hashes; nono and seccomp versions; actual Landlock ABI and ruleset status; bootstrap outcome; PID identity; start and end time; and exit status.

Audit verification must be usable without private backend access. A verifier can validate signatures, checkpoint consistency, capability binding, and enforcement evidence from public metadata and configured trust roots.

## 12. Migration

1. Land generic Merkle consistency proofs and fixed vectors in `chio-core-types` without changing existing inclusion-proof wire formats.
2. Introduce key-log shadow publication and stateful witnesses. Existing authority verification remains primary until contiguous full-log synchronization, strict-majority witnessed checkpoints, and configured gossip monitors have been observed. Test a pending rotation through witnessed activation before cutover.
3. Provision one credential through authenticated `EncryptedBlobSecretBackend`, introduce broker capabilities for that provider in audit-only routing, and prove crash reconciliation. Cut tools over provider by provider, then remove their direct credential environment and file access.
4. Add typed cage permission and retained-FD validation while legacy native launch remains explicitly configured. Generate sealed cage-init plans and compare them with observed requirements without executing targets.
5. Require broker-only credentials before requiring cage launch. Then enable cage enforcement per server. There is no automatic fallback to legacy launch after enforcement becomes required.
6. Coordinate with active-defense Phase 2 so `ToolDefinition` has one normative core shape reexported by `chio-manifest`. Only after all native servers use the full signed platform manifest may the older `chio-core-types::manifest::ToolManifest` path be deprecated or converged.

Rollback disables admission of the new feature before a launch or execution. It must not reinterpret a failed broker or cage operation as permission to use the old raw-secret or unconfined path.

## 13. Behavioral evidence and release gates

### Keyring

- Fixed RFC 6962 inclusion and consistency vectors, cross-checked against the existing tree.
- Property tests for append-only roots, complete-envelope hashing, proof verification, contiguous synchronization, transactional failure, two-stage rotation, signing-versus-activation epoch races, stale workers, event replay, sequence and predecessor rejection, algorithm mismatch, overlap, trusted artifact-time anchoring, revocation, and emergency recovery.
- Stateful strict-majority witness tests in which durable pins and gossip detect conflicting checkpoints and prevent double signing after restart.
- Release gate: a verifier updates from an old pinned checkpoint to a witnessed new checkpoint using the consistency proof and every contiguous new envelope, rebuilds the root and full state, and refuses every omission, regression, fork, backdated old-key artifact, or insufficient-witness case.

### Secret broker

- Process-level test proving the agent and tool environment, argv, files, IPC frames, logs, panic output, and receipts never contain a seeded credential.
- Concurrent max-execution test using one multi-key authoritative hold showing exactly N broker-quota captures, no duplicate parent-aggregate charge, and denial on every exhausted member. A production-adapter test rejects non-authoritative support.
- Crash tests at every pending-intent, remote hold, reverse, capture, and local reconciliation boundary prove no unknown hold can be retried as a new side effect.
- Replay, expiry, leaf-parent revocation, every delegation-ancestor revocation, broker-capability revocation, capture-set omission or mutation, combined revocation-capture races in both linearization orders, proof mismatch, body/header/option mismatch, path/query mismatch, forbidden header, redirect, response-size, SSRF, and DNS-rebinding tests.
- Production encrypted-blob tests cover authenticated provisioning, tenant isolation, tamper rejection, sealed-FD custody, wrong key, startup without custody, version rotation, redacted audit, and zeroization.
- Tripwire test proving detection and revocation happen before authenticated dispatch.
- Release gate: a fake upstream observes the credential injected by the broker while the calling tool process cannot read it from any supported interface.

### Cage

- Linux CI on a documented kernel with required Landlock ABI and seccomp enabled. Unsupported-host tests assert denial, not skip-as-success.
- Cage-init probes for forbidden reads, writes, creates, renames, symlink and path-swap escapes, network connections, syscalls, inherited FDs, parent environment values, dynamic-loader injection, and undeclared target exec.
- Bootstrap tests cover helper identity substitution, target path replacement after validation, FD identity mismatch, memfd seal failure, non-single-threaded init, partial Landlock, seccomp failure, malformed status, timeout, EOF before prepared, helper death after prepared, missing or forged exec event, prepared then structured exec failure, successful kernel-observed exec plus CLOEXEC EOF, immediate target exit, signal forwarding, and reaping.
- Release gate: caught-mutant tests demonstrate that disabling each enforcement step causes the adversarial suite to fail.

Shell scripts may orchestrate these tests and validate signed machine-readable evidence. Grep-only gates do not count as security evidence.

## 14. Provenance and licensing

The design adapts patterns from the local Clawdstrike checkout at `/Users/connor/Medica/backbay/standalone/clawdstrike`, including broker request constraints, provider-owned credential injection, Merkle consistency proofs, rotation overlap, audit monitoring, capability compilation, preflight, and supervised execution. Clawdstrike is Apache-2.0 and carries a Backbay Industries NOTICE.

For copied or substantially adapted source:

- preserve applicable copyright and license headers;
- add the Clawdstrike attribution to Chio's NOTICE and mark modified files as modified where Apache-2.0 requires it;
- record source path and source commit in the implementation commit or a provenance file;
- do not copy Spine files until the provenance and license of their stated AegisNet source is established;
- prefer a pinned upstream `nono` dependency. If Chio must vendor or patch nono, include its Apache-2.0 license, Luke Hinds attribution, upstream URL and commit, a patch inventory, and cargo-deny coverage.

The pinned nono integration must change two upstream semantics for Chio: network starts blocked, and partial filesystem enforcement is an error. These requirements must be implemented in an upstream contribution, a documented fork, or a wrapper API that can observe and reject the real ruleset status. Merely assuming the behavior is prohibited.

## 15. Residual risks

- The broker remains a high-value credential and egress target. Process isolation reduces exposure but does not remove TCB risk.
- Static syscall profiles can break diverse runtimes and can still permit dangerous behavior inside allowed syscalls. Profiles require per-runtime evidence and review.
- Landlock is not a complete container boundary and does not filter hostnames. Deployment may require namespaces, cgroups, a dedicated UID, and an egress proxy in addition to this v1 contract.
- A witness set controlled by one operator does not prevent split views. Operational independence is a deployment requirement.
- Transparent rotation makes compromise visible but does not undo artifacts signed before revocation. Verifiers need artifact-time policy and revocation semantics.
