# @chio/passkey

Browser helper for the M10 hardware-custody flow.

The package presents a passkey assertion to a server-side Chio issuer (the
only authority that holds signing material) and returns the issuer-minted
`PasskeyCapability` so the caller can attach it to subsequent kernel
requests.

## Trust boundary

The browser holds **zero** key material. The only crypto primitive touched
here is `navigator.credentials.get`, which is platform-side and never
returns a private key to the page. No envelope is signed in the browser;
the reviewer-visible verdict at
[`docs/trust-boundary-browser-signing.md`](../../../../../../docs/trust-boundary-browser-signing.md)
(status: `rejected`, 2026-04-27) explicitly forbids browser-side signing.
The M10 follow-on milestone satisfies that verdict by issuing
audience-pinned capabilities server-side; this package is the thin call
site for that flow.

## Status

- M10.P3.T1: package scaffold (this commit)
- M10.P3.T2: `requestCapability` implementation
- M10.P3.T3: demo page + Playwright e2e
- M10.P3.T4: revocation cascade e2e
- M10.P3.T5: 30 KB gzipped size budget
- M10.P3.T6: typed `urn:chio:error:custody:*` codes
