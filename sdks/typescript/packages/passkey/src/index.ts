// @chio/passkey
//
// Browser helper for the M10 hardware-custody flow. The package presents a
// passkey assertion to a server-side issuer (the only authority that holds
// signing material) and returns the issuer-minted PasskeyCapability so the
// caller can attach it to subsequent kernel requests.
//
// Trust contract (do not break):
//
//   * The browser holds ZERO key material. The only crypto primitive
//     touched here is navigator.credentials.get, which is platform-side
//     and never returns a private key to the page.
//   * No envelope is signed in the browser. The reviewer-visible verdict
//     at docs/trust-boundary-browser-signing.md (status: rejected,
//     2026-04-27) explicitly forbids this. The follow-on milestone (M10)
//     satisfies the verdict by issuing audience-pinned capabilities
//     server-side. This package is the thin call site for that flow.
//   * The capability returned to the caller is parsed via
//     parseCapabilityToken (peer dep @chio-protocol/browser, with a local
//     fail-closed fallback for environments that have not installed the
//     peer). Either path returns a structurally validated envelope; it
//     does NOT verify the issuer signature. Signature verification is the
//     kernel's job.

export type { RequestCapabilityOptions, PasskeyCapability } from './request.js';
export { requestCapability, RequestCapabilityError } from './request.js';
export { parseCapabilityToken } from './parse.js';
export {
  CHIO_CUSTODY_ERROR_CODES,
  ChioCustodyError,
  isCustodyErrorCode,
  toChioCustodyError,
} from './errors.js';
export type { CustodyErrorCode } from './errors.js';
