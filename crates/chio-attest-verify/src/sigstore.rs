//! Production [`AttestVerifier`] implementation backed by `sigstore-rs`.
//!
//! Three verification surfaces are exposed:
//!
//! - [`SigstoreVerifier::verify_bundle`] performs the full keyless flow
//!   against a Sigstore protobuf Bundle (cert chain + signature + Rekor
//!   transparency entry). This is the strongest assertion the crate
//!   provides and is the recommended entry point for new consumers.
//!
//! - [`SigstoreVerifier::verify_blob`] and [`SigstoreVerifier::verify_bytes`]
//!   verify a detached `(artifact, signature, leaf-cert)` triple against
//!   the embedded Fulcio trust root. They perform certificate-chain
//!   validation, OIDC issuer match, identity SAN regex match, certificate
//!   validity-window check, and signature verification, but DO NOT consume
//!   a Rekor inclusion proof and therefore mark the resulting
//!   [`VerifiedAttestation`] with `rekor_inclusion_verified = false`.
//!
//! All paths are fail-closed: any error returns one of the [`AttestError`]
//! variants. There is no path through this module that returns
//! `Ok(VerifiedAttestation)` after a partial verification.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use const_oid::ObjectIdentifier;
use pki_types::{CertificateDer, TrustAnchor, UnixTime};
use regex::Regex;
use sha2::{Digest, Sha256};
use sigstore::bundle::verify::{policy::VerificationPolicy, Verifier as AsyncBundleVerifier};
use sigstore::bundle::Bundle;
use sigstore::crypto::{CosignVerificationKey, Signature as SigstoreSignature};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use sigstore::trust::TrustRoot;
use webpki::{EndEntityCert, KeyUsage};
use x509_cert::der::Decode;
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
use x509_cert::Certificate;

use crate::{AttestError, AttestVerifier, ExpectedIdentity, VerifiedAttestation};

/// Embedded TUF trust-root materials. Checked in under `sigstore-root/` and
/// refreshed by the quarterly CODEOWNERS-reviewed re-bake job.
const EMBEDDED_TRUSTED_ROOT_JSON: &[u8] = include_bytes!("../sigstore-root/trusted_root.json");

/// OID for the Fulcio OIDC issuer extension. Documented at
/// `https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md`.
const OIDC_ISSUER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
/// OID for the Sigstore `OtherName` SAN entry.
const OTHERNAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.7");
/// EKU code-signing OID, required of every Fulcio-issued leaf.
const ID_KP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// Production [`AttestVerifier`] implementation. Built once via
/// [`SigstoreVerifier::with_embedded_root`] and shared (e.g. in an `Arc`)
/// across the kernel's tokio runtime; the type is [`Send`] + [`Sync`].
pub struct SigstoreVerifier {
    /// Pre-built collection of trusted Fulcio root certificates, used by
    /// the raw `verify_blob` / `verify_bytes` paths to chain-validate the
    /// supplied leaf certificate via [`webpki`]. Held as owned bytes so
    /// `TrustAnchor` borrows can be reconstructed per call.
    fulcio_root_ders: Arc<Vec<Vec<u8>>>,
    /// Dedicated single-thread tokio runtime for driving the async
    /// `sigstore-rs` bundle verifier from a synchronous trait method.
    runtime: tokio::runtime::Runtime,
}

impl SigstoreVerifier {
    /// Construct a verifier backed by the embedded Sigstore Public Good
    /// Instance trust root. The TUF root is shipped in-tree under
    /// `sigstore-root/trusted_root.json` and validated at build time by
    /// `build.rs`. This constructor never panics on a well-formed
    /// embedded root; a corrupted root surfaces as
    /// [`AttestError::TrustRoot`].
    pub fn with_embedded_root() -> Result<Self, AttestError> {
        let trust_root = build_trust_root()?;

        let fulcio_root_ders: Vec<Vec<u8>> = trust_root
            .fulcio_certs()
            .map_err(|_| AttestError::TrustRoot)?
            .into_iter()
            .map(|der| der.as_ref().to_vec())
            .collect();

        if fulcio_root_ders.is_empty() {
            return Err(AttestError::TrustRoot);
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(AttestError::Io)?;

        Ok(Self {
            fulcio_root_ders: Arc::new(fulcio_root_ders),
            runtime,
        })
    }

    /// Internal helper that builds an [`AsyncBundleVerifier`] from a
    /// freshly-parsed copy of the embedded trust root. A new verifier is
    /// constructed per call so that the bundle verifier's internal state
    /// never leaks between concurrent `verify_*` invocations. The
    /// per-call parse cost is negligible compared with the network and
    /// crypto work that follows in the typical `verify_bundle` flow.
    fn build_bundle_verifier(&self) -> Result<AsyncBundleVerifier, AttestError> {
        let trust_root = build_trust_root()?;
        AsyncBundleVerifier::new(Default::default(), trust_root).map_err(|_| AttestError::TrustRoot)
    }
}

fn build_trust_root() -> Result<SigstoreTrustRoot, AttestError> {
    SigstoreTrustRoot::from_trusted_root_json_unchecked(EMBEDDED_TRUSTED_ROOT_JSON)
        .map_err(|_| AttestError::TrustRoot)
}

impl AttestVerifier for SigstoreVerifier {
    fn verify_blob(
        &self,
        artifact: &Path,
        signature: &Path,
        certificate: &Path,
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        let artifact_bytes = fs::read(artifact)?;
        let signature_bytes = fs::read(signature)?;
        let certificate_bytes = fs::read(certificate)?;
        self.verify_bytes(
            &artifact_bytes,
            &signature_bytes,
            &certificate_bytes,
            expected,
        )
    }

    fn verify_bytes(
        &self,
        artifact: &[u8],
        signature: &[u8],
        certificate_pem: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        // 1) Parse leaf certificate (PEM or DER).
        let leaf_der = parse_certificate_to_der(certificate_pem)?;
        let leaf_cert = Certificate::from_der(&leaf_der)
            .map_err(|e| AttestError::Malformed(format!("leaf cert DER parse: {e}")))?;

        // 2) Validate against the embedded Fulcio root chain via webpki.
        validate_against_fulcio(&leaf_der, self.fulcio_root_ders.as_ref())?;

        // 3) Identity / OIDC issuer policy. Build the regex once and
        //    walk the SAN extension; reject if no SAN entry matches.
        let identity = match_identity(&leaf_cert, expected)?;

        // 4) Certificate validity window check.
        let (not_before, not_after) = certificate_validity(&leaf_cert)?;
        let now = SystemTime::now();
        if now < not_before || now > not_after {
            return Err(AttestError::CertificateExpired);
        }

        // 5) Signature verification. Cosign emits base64-encoded raw
        //    signatures; we accept either base64 ASCII or already-decoded
        //    bytes by trying base64 first.
        let key =
            CosignVerificationKey::try_from(&leaf_cert.tbs_certificate.subject_public_key_info)
                .map_err(|_| AttestError::Malformed("unsupported leaf public key".into()))?;

        verify_signature_bytes(&key, signature, artifact)?;

        Ok(VerifiedAttestation {
            subject_digest_sha256: Sha256::digest(artifact).into(),
            certificate_identity: identity,
            certificate_oidc_issuer: expected.certificate_oidc_issuer.clone(),
            rekor_log_index: 0,
            rekor_inclusion_verified: false,
            signed_at: not_before,
        })
    }

    fn verify_bundle(
        &self,
        artifact: &[u8],
        bundle_json: &[u8],
        expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        // 1) Parse the bundle protobuf-as-JSON. `sigstore-rs` re-exports
        //    `sigstore_protobuf_specs::dev::sigstore::bundle::v1::Bundle`
        //    which derives serde's `Deserialize` via prost-reflect.
        let bundle: Bundle = serde_json::from_slice(bundle_json)
            .map_err(|e| AttestError::Malformed(format!("bundle JSON parse: {e}")))?;

        // 2) Identity policy: regex-match the SAN ourselves AFTER the
        //    bundle Verifier finishes; the upstream `Identity` policy
        //    insists on an exact-string SAN match which is too narrow for
        //    keyless OIDC subjects that include a sha-pinned ref. We
        //    therefore use a permissive issuer-only policy here and
        //    reapply the regex check post-verify against the leaf SAN.
        let issuer_policy = IssuerOnlyPolicy {
            expected_issuer: expected.certificate_oidc_issuer.clone(),
        };

        // 3) Drive the async verifier. `verify_bundle` is a synchronous
        //    trait method, but `sigstore-rs`'s bundle verifier API is
        //    async, so the future must be driven by *some* runtime. The
        //    naive `self.runtime.block_on(...)` panics with "Cannot
        //    start a runtime from within a runtime" whenever the caller
        //    is itself running inside a tokio runtime (the typical case
        //    for the kernel) - even when the inner runtime is a
        //    different `Runtime` instance. Since this crate sits on a
        //    trust boundary and explicitly forbids verification-path
        //    panics via `#![forbid]` lints, we route around the panic
        //    with a runtime-detection helper (cleanup-c11d; PR #56
        //    thread r3142974715 - High Severity).
        let mut hasher = Sha256::new();
        hasher.update(artifact);
        let bundle_clone = bundle.clone();
        let verifier = self.build_bundle_verifier()?;
        run_async_bundle_verify(&self.runtime, verifier, hasher, bundle_clone, issuer_policy)
            .map_err(map_bundle_verification_error)?;

        // 4) Re-parse the bundle for metadata extraction (the verifier
        //    consumed the original by value).
        let leaf_der = bundle_leaf_certificate_der(&bundle)?;
        let leaf_cert = Certificate::from_der(&leaf_der)
            .map_err(|e| AttestError::Malformed(format!("leaf cert DER parse: {e}")))?;

        // 5) Identity SAN regex check (the upstream `Identity` policy
        //    requires exact-string match; we want regex). We also
        //    re-confirm the OIDC issuer extension.
        let identity = match_identity(&leaf_cert, expected)?;

        // 6) Pull Rekor metadata from the bundle for the receipt.
        let (rekor_log_index, signed_at) = bundle_rekor_metadata(&bundle);

        Ok(VerifiedAttestation {
            subject_digest_sha256: Sha256::digest(artifact).into(),
            certificate_identity: identity,
            certificate_oidc_issuer: expected.certificate_oidc_issuer.clone(),
            rekor_log_index,
            rekor_inclusion_verified: true,
            signed_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Drive the async `sigstore-rs` bundle verifier from a synchronous
/// trait method without panicking when the caller is itself running
/// inside a tokio runtime.
///
/// `tokio::runtime::Runtime::block_on` panics with "Cannot start a
/// runtime from within a runtime" whenever the calling thread already
/// has a tokio runtime context, even if the inner runtime is a
/// different `Runtime` instance. The two safe options are
/// `tokio::task::block_in_place` (only works on the multi-thread
/// flavor of tokio - we cannot rely on that being the caller's
/// runtime kind) and a fresh OS thread that owns its own runtime.
///
/// The strategy below picks per call:
///
/// - If `Handle::try_current()` succeeds the caller is inside a
///   runtime; we move the verifier inputs onto a fresh OS thread,
///   build a private current-thread runtime there, and join.
/// - Otherwise we drive the future on the verifier's own embedded
///   runtime (the no-runtime-in-context case, e.g. tests, CLI).
///
/// All inputs are moved by value to keep the cross-thread path
/// borrow-free; `IssuerOnlyPolicy` is a `String` wrapper and
/// `verifier` / `bundle` are owned.
fn run_async_bundle_verify(
    fallback_runtime: &tokio::runtime::Runtime,
    verifier: AsyncBundleVerifier,
    hasher: Sha256,
    bundle: Bundle,
    issuer_policy: IssuerOnlyPolicy,
) -> sigstore::bundle::verify::VerificationResult {
    if tokio::runtime::Handle::try_current().is_ok() {
        // Caller is inside a tokio runtime. A fresh OS thread with
        // its own runtime side-steps the nested-runtime panic. The
        // join handle is consumed in-line; if the new thread panics
        // mid-verify (e.g. allocator failure inside sigstore-rs) we
        // surface that as `VerificationError::Other` instead of
        // unwinding the trust-boundary caller.
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    return Err(sigstore::bundle::verify::VerificationError::Input(
                        io::Error::other(format!("spawn helper-runtime: {err}")),
                    ));
                }
            };
            rt.block_on(verifier.verify_digest(hasher, bundle, &issuer_policy, true))
        })
        .join()
        .unwrap_or_else(|_| {
            Err(sigstore::bundle::verify::VerificationError::Input(
                io::Error::other("verify helper thread panicked"),
            ))
        })
    } else {
        fallback_runtime.block_on(verifier.verify_digest(hasher, bundle, &issuer_policy, true))
    }
}

/// Accept either a PEM-armored or raw-DER certificate input. The cosign
/// CLI emits PEM by default; some pipelines double-base64-encode. We
/// strip one base64 layer if the bytes do not begin with the PEM header.
fn parse_certificate_to_der(input: &[u8]) -> Result<Vec<u8>, AttestError> {
    // Fast path: input is already PEM-armored.
    if let Ok(parsed) = pem::parse(input) {
        if parsed.tag() == "CERTIFICATE" {
            return Ok(parsed.into_contents());
        }
    }

    // Fallback: raw DER (starts with the SEQUENCE tag 0x30).
    if input.first() == Some(&0x30) {
        return Ok(input.to_vec());
    }

    Err(AttestError::Malformed(
        "certificate is neither PEM nor DER".into(),
    ))
}

fn validate_against_fulcio(
    leaf_der: &[u8],
    fulcio_root_ders: &[Vec<u8>],
) -> Result<(), AttestError> {
    let trust_anchors: Vec<TrustAnchor<'_>> = fulcio_root_ders
        .iter()
        .map(|bytes| {
            let der = CertificateDer::from(bytes.as_slice());
            webpki::anchor_from_trusted_cert(&der).map(|a| a.to_owned())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AttestError::TrustRoot)?;

    let leaf_der_handle = CertificateDer::from(leaf_der);
    let end_entity = EndEntityCert::try_from(&leaf_der_handle)
        .map_err(|_| AttestError::Malformed("leaf cert is not a valid EE cert".into()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AttestError::CertificateExpired)?;
    let unix_now = UnixTime::since_unix_epoch(now);

    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &[],
            unix_now,
            KeyUsage::required(ID_KP_CODE_SIGNING.as_bytes()),
            None,
            None,
        )
        .map_err(map_webpki_error)?;

    Ok(())
}

fn map_webpki_error(err: webpki::Error) -> AttestError {
    match err {
        webpki::Error::CertNotValidYet { .. } | webpki::Error::CertExpired { .. } => {
            AttestError::CertificateExpired
        }
        webpki::Error::UnknownIssuer => AttestError::TrustRoot,
        _ => AttestError::Malformed(format!("certificate chain validation: {err:?}")),
    }
}

fn match_identity(cert: &Certificate, expected: &ExpectedIdentity) -> Result<String, AttestError> {
    // 1) OIDC issuer extension MUST exactly equal the expected issuer.
    // The OIDC issuer is a public well-known URL (e.g. https://token.actions.githubusercontent.com),
    // not secret material. Plain `!=` is acceptable; constant-time equality is unnecessary because
    // there is no secret on either side of the comparison whose timing leak would matter.
    let issuer = read_oidc_issuer_extension(cert)?;
    if issuer != expected.certificate_oidc_issuer {
        return Err(AttestError::IssuerMismatch);
    }

    // 2) Build an anchored regex against the caller-supplied pattern.
    let anchored = format!("^(?:{})$", expected.certificate_identity_regexp);
    let regex = Regex::new(&anchored)
        .map_err(|e| AttestError::Malformed(format!("identity regex compile: {e}")))?;

    // 3) Walk the SAN extension and find the first matching entry.
    let san_match = cert
        .tbs_certificate
        .get::<SubjectAltName>()
        .map_err(|e| AttestError::Malformed(format!("SAN extension parse: {e}")))?;

    let Some((_critical, san)) = san_match else {
        return Err(AttestError::IdentityMismatch);
    };

    for name in san.0.iter() {
        let candidate: Option<String> = match name {
            GeneralName::Rfc822Name(s) => Some(s.as_str().to_owned()),
            GeneralName::UniformResourceIdentifier(s) => Some(s.as_str().to_owned()),
            GeneralName::OtherName(other) if other.type_id == OTHERNAME_OID => {
                std::str::from_utf8(other.value.value())
                    .ok()
                    .map(|s| s.to_owned())
            }
            _ => None,
        };

        if let Some(candidate) = candidate {
            if regex.is_match(&candidate) {
                return Ok(candidate);
            }
        }
    }

    Err(AttestError::IdentityMismatch)
}

fn read_oidc_issuer_extension(cert: &Certificate) -> Result<String, AttestError> {
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| AttestError::Malformed("certificate has no extensions".into()))?;

    for ext in extensions.iter() {
        if ext.extn_id == OIDC_ISSUER_OID {
            let bytes = ext.extn_value.as_bytes();
            return decode_oidc_issuer_value(bytes);
        }
    }

    Err(AttestError::IssuerMismatch)
}

/// Decode the bytes of the Fulcio OIDC issuer X.509 extension. Real-world
/// Fulcio leaves wrap the issuer as a DER UTF8String (tag 0x0C); some
/// older / hand-rolled emitters embed the raw UTF-8 directly. The DER
/// path is tried FIRST so that an extension carrying the DER prefix
/// (`0x0C <len> ...`) is not silently misread as raw UTF-8: `0x0C` is a
/// valid ASCII byte (form feed), so a naive `str::from_utf8` +
/// `is_ascii()` filter would return the bytes including the tag/length
/// prefix and produce a malformed issuer that fails string equality
/// downstream (cleanup-c11d; PR #56 review thread r3142968181 - P1).
fn decode_oidc_issuer_value(bytes: &[u8]) -> Result<String, AttestError> {
    // 1) DER UTF8String first.
    if let Ok(parsed) = x509_cert::der::asn1::Utf8StringRef::from_der(bytes) {
        return Ok(parsed.as_str().to_owned());
    }

    // 2) Fall back to raw UTF-8. Reject empty / non-printable strings;
    //    a real OIDC issuer is a URL, never empty and never starts with
    //    a control byte.
    if let Ok(direct) = std::str::from_utf8(bytes) {
        if !direct.is_empty() && direct.chars().all(|c| !c.is_control()) {
            return Ok(direct.to_owned());
        }
    }

    Err(AttestError::Malformed(
        "OIDC issuer extension is neither DER UTF8String nor printable raw UTF-8".into(),
    ))
}

fn certificate_validity(cert: &Certificate) -> Result<(SystemTime, SystemTime), AttestError> {
    let validity = &cert.tbs_certificate.validity;
    let not_before = UNIX_EPOCH + validity.not_before.to_unix_duration();
    let not_after = UNIX_EPOCH + validity.not_after.to_unix_duration();
    Ok((not_before, not_after))
}

fn verify_signature_bytes(
    key: &CosignVerificationKey,
    signature: &[u8],
    msg: &[u8],
) -> Result<(), AttestError> {
    // Try base64 first (cosign emits base64). Fall back to raw bytes.
    let base64_attempt = key.verify_signature(SigstoreSignature::Base64Encoded(signature), msg);
    if base64_attempt.is_ok() {
        return Ok(());
    }
    key.verify_signature(SigstoreSignature::Raw(signature), msg)
        .map_err(|_| AttestError::SignatureMismatch)
}

fn bundle_leaf_certificate_der(bundle: &Bundle) -> Result<Vec<u8>, AttestError> {
    use sigstore_protobuf_specs_compat::leaf_der;
    leaf_der(bundle).ok_or_else(|| AttestError::Malformed("bundle has no leaf certificate".into()))
}

fn bundle_rekor_metadata(bundle: &Bundle) -> (u64, SystemTime) {
    use sigstore_protobuf_specs_compat::rekor_metadata;
    let (index, integrated) = rekor_metadata(bundle).unwrap_or((0, 0));
    let signed_at = if integrated > 0 {
        UNIX_EPOCH + Duration::from_secs(integrated as u64)
    } else {
        SystemTime::now()
    };
    (index, signed_at)
}

fn map_bundle_verification_error(err: sigstore::bundle::verify::VerificationError) -> AttestError {
    use sigstore::bundle::verify::VerificationError as VE;

    // The inner error kinds (`CertificateErrorKind`, `SignatureErrorKind`,
    // `BundleErrorKind`) live in a private module of `sigstore-rs` so we
    // cannot pattern-match on their variants. Inspect the rendered error
    // string to disambiguate the most common cases (cert expiry, Rekor
    // inclusion); fall back to a coarse-grained mapping otherwise.
    let rendered = err.to_string().to_ascii_lowercase();
    match err {
        VE::Input(e) => AttestError::Io(io::Error::other(e.to_string())),
        VE::Bundle(_) => AttestError::Malformed(format!("sigstore bundle: {rendered}")),
        VE::Certificate(_) => {
            if rendered.contains("expired") {
                AttestError::CertificateExpired
            } else {
                AttestError::TrustRoot
            }
        }
        VE::Signature(_) => {
            if rendered.contains("transparency") {
                AttestError::RekorInclusion
            } else {
                AttestError::SignatureMismatch
            }
        }
        VE::Policy(_) => AttestError::IssuerMismatch,
    }
}

/// `sigstore-rs` re-exports the protobuf bundle struct without surface
/// helpers for digging out the leaf cert / rekor index, so we walk the
/// generated structs directly. Encapsulated in this submodule to keep
/// the field-level pattern matches isolated from the verifier flow.
mod sigstore_protobuf_specs_compat {
    use sigstore::bundle::Bundle;
    use sigstore_protobuf_specs::dev::sigstore::bundle::v1::verification_material;

    pub(super) fn leaf_der(bundle: &Bundle) -> Option<Vec<u8>> {
        let material = bundle.verification_material.as_ref()?;
        match material.content.as_ref()? {
            verification_material::Content::X509CertificateChain(chain) => chain
                .certificates
                .first()
                .map(|cert| cert.raw_bytes.clone()),
            verification_material::Content::Certificate(cert) => Some(cert.raw_bytes.clone()),
            // Future bundle profiles (e.g. raw `PublicKey`) cannot be
            // chain-validated and so are rejected here. The verifier
            // surfaces this as `AttestError::Malformed`.
            _ => None,
        }
    }

    pub(super) fn rekor_metadata(bundle: &Bundle) -> Option<(u64, i64)> {
        let material = bundle.verification_material.as_ref()?;
        let entry = material.tlog_entries.first()?;
        Some((entry.log_index as u64, entry.integrated_time))
    }
}

/// Issuer-only verification policy: confirms that the certificate carries
/// an OIDC issuer extension matching the caller's expected issuer string,
/// and defers SAN matching to [`match_identity`] (which supports regex).
struct IssuerOnlyPolicy {
    expected_issuer: String,
}

impl VerificationPolicy for IssuerOnlyPolicy {
    fn verify(
        &self,
        cert: &x509_cert::Certificate,
    ) -> Result<(), sigstore::bundle::verify::PolicyError> {
        use sigstore::bundle::verify::PolicyError;

        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or(PolicyError::ExtensionNotFound)?;

        for ext in extensions.iter() {
            if ext.extn_id == OIDC_ISSUER_OID {
                let bytes = ext.extn_value.as_bytes();
                // Use the same DER-first decoder as
                // `read_oidc_issuer_extension`: trying raw UTF-8 first
                // silently mis-reads DER UTF8String wrappers because
                // the tag byte (0x0C) is ASCII (cleanup-c11d; PR #56
                // thread r3142968181). Decoder failure surfaces as
                // ExtensionNotFound to match the upstream policy
                // contract.
                let actual = match decode_oidc_issuer_value(bytes) {
                    Ok(s) => s,
                    Err(_) => return Err(PolicyError::ExtensionNotFound),
                };
                // Plain `==` on a public OIDC issuer URL: no secret-material timing channel.
                if actual == self.expected_issuer {
                    return Ok(());
                }
                return Err(PolicyError::ExtensionCheckFailed {
                    extension: "OIDCIssuer".to_owned(),
                    expected: self.expected_issuer.clone(),
                    actual,
                });
            }
        }
        Err(PolicyError::ExtensionNotFound)
    }
}

// Bring `Identity` into scope for downstream consumers that may want to
// build their own policies on top of the shared trust root. This re-export
// is intentional and stable.
#[allow(unused_imports)]
pub use sigstore::bundle::verify::policy::Identity as SigstoreIdentityPolicy;
