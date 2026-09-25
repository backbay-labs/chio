# Revoke an agent's access while its application is running

Save a note through Chio's HTTP gateway, revoke the actual grant used for that
write, and repeat the same request. The second write is refused and the note
store is unchanged. The application then restarts the services and verifies that
revocation persists. Finally, it stops the authority and verifies that a fresh,
otherwise valid grant cannot write while revocation status is unavailable.

From this directory, with Python 3.11+, uv and the Chio CLI built from this checkout:

```bash
uv run --locked run.py "Review the deployment checklist"
```

Set `CHIO_BIN` if the executable is outside your PATH. Run the command again with
your own note; existing notes, identities and receipts remain in `.state/`.
The launcher starts and stops only its own local processes. It chooses available
ports and configures the authority and gateway through supported CLI options.

## Read the application

- `notes.py` is a small SQLite-backed HTTP service. It has no Chio dependency.
- `openapi.yaml` declares the routes and marks writes as protected operations.
- `run.py` generates persistent Ed25519 identities, starts the trust service and
  gateway, requests a grant for its caller, then drives the application flow.
- `.state/runs/<run-id>/verification.json` retains four complete signed HTTP
  receipts and their verification results. The gateway key is selected by the
  operator before any request; a receipt cannot establish its own trust.

The signed HTTP receipt ID is the `X-Chio-Receipt-Id` response header. HTTP
receipts use their own wire format; verify them with the Python SDK's
`verify_http_receipt_with_trusted_signers`. A verified refusal is a valid record,
not authorization to execute. Inspect `authorized` and the signed verdict.

The application owns approval and task logic. Chio checks the presented grant,
queries live revocations before admission, records its decisions and blocks
refused requests before they reach the notes service.
