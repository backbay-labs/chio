# @chio-protocol/passkey

Browser helper for the Chio hardware-custody flow.

The package presents a passkey assertion to a server-side Chio issuer (the
only authority that holds signing material) and returns the issuer-minted
`PasskeyCapability` so the caller can attach it to subsequent kernel
requests.

## Trust boundary

The browser holds **zero** key material. The only crypto primitive touched
here is `navigator.credentials.get`, which is platform-side and never
returns a private key to the page. No envelope is signed in the browser;
the reviewer-visible verdict at
[`docs/trust-boundary-browser-signing.md`](../../../../docs/trust-boundary-browser-signing.md)
(status: `rejected`, 2026-04-27) explicitly forbids browser-side signing.
The hardware-custody design satisfies that verdict by issuing
audience-pinned capabilities server-side; this package is the thin call
site for that flow.

## Surface

- Package scaffold and typed exports
- `requestCapability` request/response helper
- Demo page and Playwright e2e harness
- Revocation cascade e2e coverage
- 30 KB gzipped size budget
- Typed `urn:chio:error:custody:*` codes
