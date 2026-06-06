use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chio_core::appraisal::{
    derive_runtime_attestation_appraisal, AttestationVerifierFamily, RuntimeAttestationAppraisal,
    RuntimeAttestationAppraisalReasonCode, ENTERPRISE_VERIFIER_ADAPTER,
    ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA, GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
    GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
};
use chio_core::capability::{
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    workload_identity::{WorkloadCredentialKind, WorkloadIdentity},
};
use chio_core::crypto::PublicKey;
use chio_core::receipt::lineage::SignedExportEnvelope;
use ciborium::de::from_reader as cbor_from_reader;
use ciborium::ser::into_writer as cbor_into_writer;
use ciborium::value::{Integer as CborInteger, Value as CborValue};
use p384::ecdsa::{
    signature::Verifier as _, Signature as P384Signature, VerifyingKey as P384VerifyingKey,
};
use rsa::pkcs1v15::VerifyingKey as RsaPkcs1v15VerifyingKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::VerifyingKey as RsaPssVerifyingKey;
use rsa::{pkcs1v15::Signature as RsaPkcs1v15Signature, pss::Signature as RsaPssSignature};
use rsa::{BigUint, RsaPublicKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode as _, DecodePem as _, Encode as _};
use x509_cert::Certificate;

pub const AZURE_MAA_ATTESTATION_SCHEMA: &str = "chio.runtime-attestation.azure-maa.jwt.v1";
pub const AZURE_MAA_VERIFIER_ADAPTER: &str = "azure_maa";
pub const AWS_NITRO_ATTESTATION_SCHEMA: &str = "chio.runtime-attestation.aws-nitro-attestation.v1";
pub const AWS_NITRO_VERIFIER_ADAPTER: &str = "aws_nitro";

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedRuntimeAttestation {
    pub evidence: RuntimeAttestationEvidence,
    pub appraisal: RuntimeAttestationAppraisal,
}

pub trait RuntimeAttestationVerifierAdapter {
    type Error;

    fn adapter_name(&self) -> &'static str;

    fn verifier_family(&self) -> AttestationVerifierFamily;

    fn verify_and_appraise(
        &self,
        evidence: &str,
        now: u64,
    ) -> Result<VerifiedRuntimeAttestation, Self::Error>;
}

#[path = "attestation/model.rs"]
mod model;
pub use model::*;
#[path = "attestation/verification.rs"]
mod verification;
pub use verification::*;
#[cfg(test)]
#[path = "attestation/tests.rs"]
mod tests;
