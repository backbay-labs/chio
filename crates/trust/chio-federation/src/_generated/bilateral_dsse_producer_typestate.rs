// DO NOT EDIT - regenerate via 'cargo xtask codegen rust'.
//
// Source: spec/statemachines/bilateral_dsse_producer.toml
// Tool:   chio-spec-codegen state machine pass
// Owner:  crates/trust/chio-federation
//
// Manual edits will be overwritten.

//! Ordered states for Bilateral DSSE producer.
//!
//! The strict bilateral DSSE producer from canonical statement construction through local host signing, origin co-signing, and final envelope verification.
/// Skipping an intermediate state does not compile.
///
/// ```compile_fail
/// use chio_federation::bilateral_dsse::typestate::Drafted;
/// fn skip(state: Drafted<'_>) {
///     let _ = state.request_cosignature();
/// }
/// ```
/// A terminal state cannot repeat its terminal transition.
///
/// ```compile_fail
/// use chio_federation::bilateral_dsse::typestate::EnvelopeVerified;
/// fn repeat(state: EnvelopeVerified) {
///     let _ = state.verify_envelope();
/// }
/// ```
pub struct Drafted<'a> {
    data: crate::bilateral_dsse::typestate_handlers::DraftedData<'a>,
}
pub struct HostSigned<'a> {
    data: crate::bilateral_dsse::typestate_handlers::HostSignedData<'a>,
}
pub struct Cosigned<'a> {
    data: crate::bilateral_dsse::typestate_handlers::CosignedData<'a>,
}
pub struct EnvelopeVerified {
    output: crate::bilateral_dsse::DsseEnvelope,
}
impl<'a> Drafted<'a> {
    pub(crate) fn from_data(
        data: crate::bilateral_dsse::typestate_handlers::DraftedData<'a>,
    ) -> Self {
        Self { data }
    }
    /// Consume `Drafted` and enter `HostSigned`. Runtime guards: host_signature_created.
    pub fn sign_host(self) -> Result<HostSigned<'a>, crate::bilateral::BilateralCoSigningError> {
        let data = crate::bilateral_dsse::typestate_handlers::sign_host(self.data)?;
        Ok(HostSigned { data })
    }
}
impl<'a> HostSigned<'a> {
    /// Consume `HostSigned` and enter `Cosigned`. Runtime guards: cosigning_schema_matches, origin_signature_valid.
    pub fn request_cosignature(
        self,
    ) -> Result<Cosigned<'a>, crate::bilateral::BilateralCoSigningError> {
        let data = crate::bilateral_dsse::typestate_handlers::request_cosignature(self.data)?;
        Ok(Cosigned { data })
    }
}
impl<'a> Cosigned<'a> {
    /// Consume `Cosigned` and enter `EnvelopeVerified`. Runtime guards: signer_keys_independent, strict_envelope_valid.
    pub fn verify_envelope(
        self,
    ) -> Result<EnvelopeVerified, crate::bilateral::BilateralCoSigningError> {
        let output = crate::bilateral_dsse::typestate_handlers::verify_envelope(self.data)?;
        Ok(EnvelopeVerified { output })
    }
}
impl EnvelopeVerified {
    #[must_use]
    pub fn into_envelope(self) -> crate::bilateral_dsse::DsseEnvelope {
        self.output
    }
}
