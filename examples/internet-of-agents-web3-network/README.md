# A network that can delegate work and settle its result

Run four persistent Chio kernel hosts with real passport admission, bounded
subcontracting, operator approval, local-chain escrow and independent auditing.
The new application uses each host's actual receipts and the Chio contracts it
deploys in this run. It preserves the source of every work product and payment.

With the matching Chio CLI installed, Rust 1.94.1, Node.js 22+ and uv:

```sh
python3 orchestrate.py
```

The same workflow is available with `./smoke.sh`. Both start the current
[application](application/README.md), retain its state and stop only the processes
they own. The launcher creates a new private directory for every run.

## What you can build from it

- An admission broker that verifies a native Chio passport, holder challenge and
  bilateral evidence before awarding work.
- A provider that delegates one narrower review responsibility through a signed
  two-hop chain. Revoking the parent blocks the specialist after restart.
- A treasury that requires exact independent invoice approval and reserves
  exposure durably before publishing a payment.
- A settlement service that binds the actual review receipt to an escrow proof,
  handles partial acceptance and refunds, and recovers interrupted publications.
- An auditor that retrieves each exact request and response from the serving
  host, verifies the selected signer and rejects missing or substituted records.

Read [the complete application guide](application/README.md) for the code map,
expected behavior, negative controls and independent artifact verification.
The [historical fixture console](LEGACY.md) is retained separately for format
reference; it is not the current execution path.
