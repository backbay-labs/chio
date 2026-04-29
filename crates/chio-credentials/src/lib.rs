//! Portable reputation credentials and Agent Passport verification for Chio.
//!
//! The native Chio passport format remains intentionally simple:
//! - credentials are canonically JSON-signed with Ed25519
//! - issuer and subject identities currently remain `did:chio` identifiers
//! - a passport is an unsigned bundle of independently verifiable credentials
//! - verification is pure and requires no kernel or storage dependency
//!
//! Chio also ships a narrower standards-native projection lane for external
//! OID4VCI-style issuance. That path remains derived from the native passport
//! artifact rather than replacing it as the source of truth.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use chio_core::{
    canonical_json_bytes,
    session::{ChioIdentityAssertion, EnterpriseFederationMethod, EnterpriseIdentityContext},
    sha256_hex, ChioPortableClaimCatalog, ChioPortableIdentityBinding, Keypair, PublicKey,
    Signature,
};
use chio_did::{DidChio, DidError};
use chio_reputation::{
    BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
    IncidentCorrelationMetrics, LeastPrivilegeMetrics, LocalReputationScorecard, MetricValue,
    ReliabilityMetrics, ResourceStewardshipMetrics, SpecializationMetrics,
};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use serde::{Deserialize, Serialize};

const VC_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";
const CHIO_CREDENTIAL_CONTEXT_V1: &str = "https://chio.dev/credentials/v1";
const VC_TYPE: &str = "VerifiableCredential";
const REPUTATION_ATTESTATION_TYPE: &str = "ChioReputationAttestation";
const PASSPORT_SCHEMA: &str = "chio.agent-passport.v1";
const LEGACY_PASSPORT_SCHEMA: &str = "chio.agent-passport.v1";
const PASSPORT_VERIFIER_POLICY_SCHEMA: &str = "chio.passport-verifier-policy.v1";
const LEGACY_PASSPORT_VERIFIER_POLICY_SCHEMA: &str = "chio.passport-verifier-policy.v1";
const PASSPORT_PRESENTATION_CHALLENGE_SCHEMA: &str =
    "chio.agent-passport-presentation-challenge.v1";
const LEGACY_PASSPORT_PRESENTATION_CHALLENGE_SCHEMA: &str =
    "chio.agent-passport-presentation-challenge.v1";
const PASSPORT_PRESENTATION_RESPONSE_SCHEMA: &str = "chio.agent-passport-presentation-response.v1";
const LEGACY_PASSPORT_PRESENTATION_RESPONSE_SCHEMA: &str =
    "chio.agent-passport-presentation-response.v1";
const CROSS_ISSUER_PORTFOLIO_SCHEMA: &str = "chio.cross-issuer-portfolio.v1";
const CROSS_ISSUER_TRUST_PACK_SCHEMA: &str = "chio.cross-issuer-trust-pack.v1";
const CROSS_ISSUER_MIGRATION_SCHEMA: &str = "chio.cross-issuer-migration.v1";
const CROSS_ISSUER_PORTFOLIO_EVALUATION_SCHEMA: &str = "chio.cross-issuer-portfolio-evaluation.v1";
const PROOF_TYPE: &str = "Ed25519Signature2020";
const PROOF_PURPOSE: &str = "assertionMethod";
const PRESENTATION_PROOF_PURPOSE: &str = "authentication";

fn is_supported_passport_schema(schema: &str) -> bool {
    schema == PASSPORT_SCHEMA || schema == LEGACY_PASSPORT_SCHEMA
}

fn is_supported_passport_verifier_policy_schema(schema: &str) -> bool {
    schema == PASSPORT_VERIFIER_POLICY_SCHEMA || schema == LEGACY_PASSPORT_VERIFIER_POLICY_SCHEMA
}

fn is_supported_passport_presentation_challenge_schema(schema: &str) -> bool {
    schema == PASSPORT_PRESENTATION_CHALLENGE_SCHEMA
        || schema == LEGACY_PASSPORT_PRESENTATION_CHALLENGE_SCHEMA
}

fn is_supported_passport_presentation_response_schema(schema: &str) -> bool {
    schema == PASSPORT_PRESENTATION_RESPONSE_SCHEMA
        || schema == LEGACY_PASSPORT_PRESENTATION_RESPONSE_SCHEMA
}

pub mod trust_tier;
pub use trust_tier::{
    synthesize_trust_tier, TrustTier, TRUST_TIER_ATTESTED_MIN, TRUST_TIER_PREMIER_MIN,
    TRUST_TIER_VERIFIED_MIN,
};

// libFuzzer entry-point module, enabled only when the `fuzz` feature is
// turned on by the standalone `chio-fuzz` workspace at `../../fuzz`.
#[cfg(feature = "fuzz")]
pub mod fuzz;

include!("artifact.rs");
include!("passport.rs");
include!("cross_issuer.rs");
include!("portable_sd_jwt.rs");
include!("portable_jwt_vc.rs");
include!("challenge.rs");
include!("registry.rs");
include!("presentation.rs");
include!("policy.rs");
include!("oid4vci.rs");
include!("oid4vp.rs");
include!("discovery.rs");
include!("portable_reputation.rs");
include!("tests.rs");
