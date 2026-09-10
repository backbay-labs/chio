# One-capability operator commands

`operator_capability.py` operates on one explicit capability through the running
MCP kernel's admin API. It reads the operator credential from a private file;
there is no token command-line argument. Keep this file outside the agent's
readable filesystem boundary. Use the capability ID retained by that session's
operator preparation, not a newly issued replacement identity.

From this directory:

```sh
python3 operator_capability.py status \
  --operator-file /private/operator/state/operator.json \
  --capability-id cap-EXACT-RETAINED-ID
python3 operator_capability.py budget \
  --operator-file /private/operator/state/operator.json \
  --capability-id cap-EXACT-RETAINED-ID
python3 operator_capability.py revoke \
  --operator-file /private/operator/state/operator.json \
  --capability-id cap-EXACT-RETAINED-ID
```

- `status` queries `/admin/revocations` with exactly one `capability_id`. A false
  revocation result does not prove that the capability exists, is unexpired or
  otherwise authorizes an action.
- `budget` queries `/admin/budgets` for that capability's per-grant usage. It does
  not change budgets or infer remaining authority from usage alone. At the
  current 200-row admin limit, `mayBeTruncated` is true; do not treat that result
  as a complete grant inventory. Optional cost counters from trust-control
  backed kernels are retained when returned.
- `revoke` posts only `{"capability_id":"..."}` to `/admin/revocations`. It does
  not revoke all capabilities, replace sessions, clear fences or redispatch work.

The private operator JSON requires a nonempty `adminToken` distinct from any
agent token and an integer `port` in 1-65535 for the default literal loopback
origin. The file must be a regular file owned by the current user, with no group
or other permissions; final-component symlinks are refused. Generated operator
files already use mode 0600. IDs are explicit 1-256 character ASCII identifiers
using letters, digits, `.`, `_`, `:`, and `-`, beginning with a letter or digit.
Wildcards, whitespace and URL syntax are refused before a request.

For another deployment, select the trusted final origin explicitly with
`--base-url https://kernel.example`. HTTPS uses normal CA and hostname
verification. Plain HTTP is permitted only for loopback addresses; `localhost`
is normalized to `127.0.0.1`. Userinfo, paths, queries, fragments, control
characters and ambiguous origins are rejected. All redirects, including those
within the same origin, fail closed. Environment HTTP/HTTPS proxies are ignored.
There is no insecure TLS mode or redirect override. The operator must select a
trusted origin; a syntactically valid HTTPS URL is not proof that its owner is
trusted with this credential.

The default network timeout is 30 seconds; `--timeout` accepts a finite positive
value up to 60 seconds. Responses must be bounded JSON objects with the requested
capability ID and valid field types. Only scoped fields appear on stdout; server
error bodies and private credentials are never echoed. A transport, HTTP or
response-validation failure returns exit 1. After an attempted revoke fails,
`outcome: unknown` conservatively means the request may have reached the server.
There is no automatic retry. Query the same capability's status and preserve the
original operator state before deciding what to do next.

`operator_approval.py` uses the same private transport. Its existing submit,
show, approve and deny payloads are preserved. It reserves a new mode-0600 output
with exclusive creation before sending a mutation, refuses to overwrite a prior
artifact, and keeps the complete successful approval response private. Stdout
contains only the output path, HTTP status, closed-vocabulary approval status and
a validated approval ID. Redirects and transport failures produce a private
failure record; an attempted mutation has an unknown outcome until reconciled.
An approval record is not itself evidence that a tool executed.

## Scope and verification

The original capability helper was commit
`bb461a53b89931eadf06be325b5c93d8f5c50d81`. This repair was based on
`7255e7aedcab8d36e99e459345f3edde55dc58a5` and checked against
`crates/protocol/chio-mcp-remote/src/remote_mcp/admin.rs` and `session_forms.rs`.
The CLI's `chio trust revoke/status` commands target a trust-control service or
local revocation database; they are not the same private-file MCP admin route.

Run the focused disposable transport tests from the repository root:

```sh
python3 -m unittest discover \
  -s integrations/required-agents/qualification -p test_operator_http.py -v
```

The tests require Python 3 and OpenSSL for a temporary localhost TLS certificate.
They verify exact request scope, all redirect codes across both helper action
sets, zero requests to a redirect/proxy sink, TLS trust, output reservation,
input and malformed-response errors, and a committed fixture revocation whose
response is lost without an automatic retry. They use no real owner, normal
profile or provider credentials. These focused tests qualify the operator
transport repair; they do not constitute host or kernel acceptance.

Local validation on 2026-09-10: all 14 focused tests passed with no skips;
`ruff check`, `ruff format --check`, and `git diff --check` passed. Existing CI
(`.github/workflows/ci.yml`) and `scripts/ci-workspace.sh` both discover
`qualification/test_*.py`, so the new suite needs no workflow change.
