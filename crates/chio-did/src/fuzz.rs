//! libFuzzer entry-point module for `chio-did`.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the
//! standalone `chio-fuzz` workspace at `../../fuzz`. The production build of
//! `chio-did` never pulls in `arbitrary`, never exposes these symbols, and
//! never gets recompiled with libFuzzer instrumentation.
//!
//! The single entry point [`fuzz_did_resolve`] consumes arbitrary bytes and
//! drives them through the four trust-boundary surfaces in `chio-did`:
//!
//! 1. [`DidChio::from_str`] - the `did:chio:<hex>` URI parser.
//! 2. [`resolve_did_arc`] - the parser-plus-resolver convenience used by
//!    callers that want the populated [`DidDocument`] for a given URI. No
//!    network resolution is involved; `did:chio` documents are fully
//!    self-certifying from the URI.
//! 3. [`DidDocument`] via [`serde_json::from_slice`] - the JSON
//!    deserialization path used whenever a DID Document arrives over the
//!    wire (cross-issuer registry sync, OID4VP issuer-document fetches,
//!    receipt-log envelopes).
//! 4. [`DidService::new`] - the [`url::Url`] validation path.
//!
//! Every path is fail-closed: invalid input must surface as an `Err(_)` or
//! a returned `Result::Err` value, never a panic, abort, or undefined
//! behaviour. This target exists to catch parse-path regressions in the
//! hex-decoding loop, the multibase encoder, the `serde_json` decoder, and
//! the URL parser.
//!
//! No network resolution is invoked. `did:chio` is self-certifying so the
//! "resolve" call is purely deterministic over the URI bytes; no other DID
//! method is exposed by this crate today, so there is no off-host
//! resolver-target surface to drive.

use std::str::FromStr;

use crate::{resolve_did_arc, DidChio, DidDocument, DidService, ResolveOptions};

/// Drive arbitrary bytes through the `chio-did` trust-boundary surface.
///
/// Bytes are interpreted in three independent ways and each interpretation
/// is forwarded to the corresponding parser. Errors at every step are
/// silently consumed: the trust-boundary contract guarantees the only
/// outcomes are `Err(DidError::*)` (good), `Err(serde_json::Error)` (good),
/// or a panic / abort (which libFuzzer surfaces as a crash). No arbitrary
/// input can produce a useful `Ok(_)`; we only care about exercising the
/// parse paths.
///
/// 1. As a UTF-8 string, the input is run through both [`DidChio::from_str`]
///    and [`resolve_did_arc`] with an empty [`ResolveOptions`]. The two
///    calls share the same parser, but `resolve_did_arc` additionally
///    exercises the multibase encoder on the success path; together they
///    cover both the URI-only and URI-plus-document trust-boundary
///    surfaces.
/// 2. As a UTF-8 string, the input is also passed to [`DidService::new`]
///    as a candidate `serviceEndpoint`, exercising the [`url::Url`]
///    validator that gates every service-endpoint string before it lands
///    in a [`DidDocument`].
/// 3. As a JSON byte slice, the input is fed to [`serde_json::from_slice`]
///    with target type [`DidDocument`], exercising the document
///    deserialization path used by every off-host DID-document consumer.
pub fn fuzz_did_resolve(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        // 1a. URI parser.
        let _ = DidChio::from_str(text);
        // 1b. URI parser plus resolve (exercises the multibase encoder on
        //     the success path).
        let _ = resolve_did_arc(text, &ResolveOptions::default());
        // 2.  Service-endpoint URL validator. Constant id/type so the only
        //     varying input is the URL bytes under test.
        let _ = DidService::new("did:chio:fuzz#endpoint", "ChioFuzzService", text);
    }
    // 3.  DID-Document JSON deserializer. Operates on the raw byte slice so
    //     non-UTF-8 inputs still drive `serde_json`'s UTF-8 validation
    //     fast-path.
    let _ = serde_json::from_slice::<DidDocument>(data);
}
