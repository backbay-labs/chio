# Agent Commerce Network

Build a procurement agent that purchases actual work from a separate provider,
accepts only verifiable deliverables, and keeps a durable record of what it owes.
The buyer is a FastAPI service. The provider is a Python source-review service
exposed through MCP. Chio mediates both boundaries and signs their operations.

## Run the application

Use Python 3.11 or newer, uv, and the Chio CLI built from the same public source
revision as this project. The project lockfile installs the matching Python SDK.

```bash
uv run --locked run.py
```

The launcher starts the authority, provider kernel, buyer API and HTTP gateway.
It generates private keys, pins the owned kernels before accepting results,
requests a quote, and purchases the included `workspace/payments-api` review.
Afterward it stops those processes and preserves `.state/`.

The first purchase costs 45000 minor units from an initial allowance of 150000.
The provider reads the actual files and returns three artifacts:

- `findings.json`: file hashes, rule matches, line numbers and recommendations.
- `executive-summary.md`: the selected checks and their actual findings.
- `remediation-checklist.md`: actions for those findings.

The buyer verifies the exact provider receipt, its signature and trusted signer,
request identity, tool arguments and output hash. It also verifies each delivered
artifact's hash. Only then does it write balanced buyer/provider book entries.
The final run verifier independently checks the HTTP and MCP records and their
associations with the quote, work and retained ledger.

These entries account for an obligation inside this application. They do not
move money on an external payment rail. The [Web3 example](../internet-of-agents-web3-network/)
is the separate on-chain settlement application.

## Use your own input

Place Python files in `workspace/my-service`, then run:

```bash
uv run --locked run.py --target my-service
```

The target is a local relative directory. The service refuses traversal, symbolic
links, unsupported scopes, empty inputs, and inputs larger than the selected
offer. It never executes the submitted Python files.

`provider/catalog.py` defines the available checks, limits and example prices:

| Offer | Actual checks | File / byte limit | Price in minor units |
| --- | --- | --- | ---: |
| hotfix-review | Python dynamic execution, shell invocation, weak digest calls | 10 / 200000 | 45000 |
| release-review | Hotfix checks plus swallowed broad exceptions | 100 / 2000000 | 125000 |
| release-plus-cloud-review | Release checks plus public/privileged settings in JSON configuration | 100 / 2000000 | 175000 |
| full-estate-review | All preceding checks plus unpinned requirements files | 500 / 5000000 | 325000 |

Each report identifies exactly which checks ran. The example's static scanner
is intentionally readable and replaceable with your own review implementation.

## Let a model procure the work

```bash
export OPENAI_API_KEY=YOUR_KEY
uv run --locked run.py --provider openai --model gpt-4.1-mini
```

`OPENAI_BASE_URL` selects a compatible endpoint. An Anthropic client is also
available with `--provider anthropic --model YOUR_MODEL`, using
`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` and optional `ANTHROPIC_BASE_URL`.
The model can request quotes, create jobs, read their state and open disputes.
It receives no independent approval credential. A failed model response, exhausted
turn limit or ambiguous job outcome cannot become a fabricated fulfillment.

## Operate the retained buyer

```bash
uv run --locked run.py status
uv run --locked run.py --scope release-review --budget 150000
uv run --locked run.py approve JOB_ID
uv run --locked run.py fund 200000
```

A quote above 100000 requires independent operator approval. The buyer reserves
its allowance while waiting. The `approve` command uses the operator-owned
launcher credential; a model's bearer grant alone cannot approve a purchase.
`fund` explicitly adds allowance and retains an allocation record. It does not
reset jobs, mint an external currency or erase the existing ledger.

Reservations are committed before provider dispatch. Concurrent purchases cannot
overspend the remaining allowance. A consumed quote cannot create another job.
A provider failure, unverifiable receipt or mismatched artifact leaves the job
`outcome_unknown` with its reservation retained. Inspect that job and the provider
records before deciding whether work completed. The application does not retry
an uncertain purchase automatically.

Opening a dispute records a request for resolution. It leaves the existing debit
in the ledger until an actual resolution occurs; it does not pretend a reversal
has already happened.

## Check the boundaries

```bash
uv run --locked run.py check
```

This starts the actual services with separate qualification state and a 500000
allowance. It checks completed work, zero/negative budgets, attempts to raise the
operator ceiling, provider substitution, quote replay, independent approval,
approval replay, concurrent reservations, revocation and provider unavailability.
Every captured HTTP operation and completed provider operation is verified against
keys selected before the requests. Your application data remains in `.state/`;
qualification runs use `.state/qualification/`.

## Read and adapt the implementation

- `buyer/app.py`: application state transitions and authoritative provider calls.
- `buyer/store.py`: durable reservations, allocations and balanced book entries.
- `provider/review.py`: actual bounded review and retained work products.
- `provider/policy.yaml`: the three specifically authorized provider operations.
- `buyer/openapi.yaml`: the buyer's HTTP operation contract.
- `commerce_network/agents.py`: direct, OpenAI Agents SDK and Anthropic workflows.
- `commerce_network/verify.py`: independent run verification.
- `run.py`: process lifecycle and local operator actions.

For integration into an existing deployment, `provider/run-edge.sh` and
`buyer/run-sidecar.sh` expose the underlying CLI wiring. Keep the buyer's direct
upstream, provider implementation and operator administration endpoints private;
clients enter through their governed boundaries.
