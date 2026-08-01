//! Core Chio protocol types: capabilities, receipts, crypto primitives, and
//! canonical JSON. This crate is `no_std + alloc` compatible; heavier domain
//! crates (`chio-core`, `chio-appraisal`, etc.) re-export these types with
//! additional features layered on top.
//!
//! # no_std support
//!
//! The crate is `no_std + alloc` by source: under `--no-default-features`
//! every module compiles against `core` and `alloc` only. This is the
//! foundation that lets `chio-kernel-core` cross-compile to
//! `wasm32-unknown-unknown` and other embedded targets. The default `std`
//! feature re-enables `std`-backed error impls via `thiserror`, along with
//! the `std` feature on every transitive dependency.
//!
//! # Generated wire bindings
//!
//! Schema-derived Rust bindings live under `src/_generated/` as regenerate-only
//! artifacts. They are not re-exported from this crate root: the stable public
//! API is the hand-maintained no_std-compatible protocol modules below.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

pub mod canonical;
pub mod capability;
pub mod crypto;
pub mod delegation_receipt;
pub mod economic_continuity;
pub mod error;
pub mod hashing;
pub mod loaded_weights;
pub mod manifest;
pub mod merkle;
#[cfg(any(kani, test))]
#[doc(hidden)]
pub mod merkle_fixtures;
pub mod merkle_steps;
pub mod message;
pub mod oracle;
pub mod plan;
#[cfg(feature = "pq")]
pub mod pq;
pub mod provider_attempt;
pub mod receipt;
pub mod runtime_attestation;
mod schema_binding;
pub mod session;
pub mod signed_artifact;
mod signer_binding;
mod store_fence;

#[cfg(test)]
#[path = "economic_continuity_anchor_tests.rs"]
mod economic_continuity_anchor_tests;
#[cfg(test)]
#[path = "economic_continuity_tests.rs"]
mod economic_continuity_tests;

pub use canonical::{
    canonical_json_bytes, canonical_json_bytes_from_str, canonical_json_string,
    canonical_json_string_from_str, canonicalize, CanonicalBytes, CanonicalJsonWitness,
};
pub use crypto::{
    sha256_hex, Ed25519Backend, Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
#[cfg(feature = "pq")]
pub use crypto::{HybridBackend, MlDsa65Backend};
#[cfg(feature = "fips")]
pub use crypto::{P256Backend, P384Backend};
pub use delegation_receipt::{DelegationReceipt, ScopeAttenuation};
pub use economic_continuity::{
    CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
pub use error::{Error, Result};
pub use hashing::{sha256, Hash};
pub use loaded_weights::{
    loaded_weights_hash_of, loaded_weights_hash_of_chunks, LoadedWeights, LoadedWeightsUnavailable,
};
pub use manifest::{
    PricingModel, ToolAnnotations, ToolDefinition, ToolManifest, ToolManifestBody, ToolPricing,
};
pub use merkle::{leaf_hash, node_hash, MerkleProof, MerkleTree};
pub use merkle_steps::{inclusion_step, InclusionStep};
pub use message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
pub use oracle::{OracleConversionEvidence, CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA};
pub use plan::{
    PlanEvaluationRequest, PlanEvaluationResponse, PlanVerdict, PlannedToolCall, PlannedToolCallId,
    StepVerdict, StepVerdictKind,
};
pub use receipt::metadata::{
    DeliveryContract, DeliveryResult, FindingDelivery, FindingDeliverySettlementMode,
    FindingMediaTypeCheck, FindingStatusProofMetadata, FindingTransformProfile,
    DELIVERY_CONTRACT_METADATA_KEY, DELIVERY_CONTRACT_SCHEMA, FINDING_DELIVERY_METADATA_KEY,
    FINDING_DELIVERY_SCHEMA,
};
pub use runtime_attestation::{
    verifier_family_for_attestation_schema, AttestationVerifierFamily,
    AWS_NITRO_ATTESTATION_SCHEMA, AWS_NITRO_VERIFIER_ADAPTER, AZURE_MAA_ATTESTATION_SCHEMA,
    AZURE_MAA_VERIFIER_ADAPTER, ENTERPRISE_VERIFIER_ADAPTER,
    ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA, GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
    GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
};
pub use session::{
    ChioIdentityAssertion, CompleteOperation, CompletionArgument, CompletionReference,
    CompletionResult, CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, ElicitationAction, EnterpriseFederationMethod, EnterpriseIdentityContext,
    GetPromptOperation, NormalizedRoot, OAuthBearerFederatedClaims, OAuthBearerSessionAuthInput,
    OperationContext, OperationKind, OperationTerminalState, ProgressToken, PromptArgument,
    PromptDefinition, PromptMessage, PromptResult, ReadResourceOperation, RequestId,
    RequestOwnershipSnapshot, ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
    ResourceUriClassification, RootDefinition, SamplingMessage, SamplingTool, SamplingToolChoice,
    SessionAuthContext, SessionAuthMethod, SessionId, SessionOperation, SessionTransport,
    StreamOwner, TaskOwnershipSnapshot, ToolCallOperation, WorkOwner,
};
pub use signed_artifact::{
    built_in_signed_artifact_registry, is_supported_signed_artifact_schema,
    validate_signed_artifact_schema, SignedArtifactSchemaEntry,
    CHIO_AGENT_WEB_PROOF_ENVELOPE_V1_SCHEMA, CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA,
    CHIO_ANCHOR_BATCH_V1_SCHEMA, CHIO_ANCHOR_INCLUSION_PROOF_V1_SCHEMA,
    CHIO_ANCHOR_INCLUSION_PROOF_V2_SCHEMA, CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA,
    CHIO_ANCHOR_PROOF_BUNDLE_V2_SCHEMA, CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA,
    CHIO_CREDIT_FACILITY_BIND_V1_SCHEMA, CHIO_FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_V1_SCHEMA,
    CHIO_FACTOR_ASSIGNMENT_AGREEMENT_V1_SCHEMA,
    CHIO_FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_V1_SCHEMA,
    CHIO_FACTOR_ASSIGNMENT_NOT_APPLIED_V1_SCHEMA, CHIO_FINDING_ADMISSION_V1_SCHEMA,
    CHIO_FINDING_BOND_BACKING_V1_SCHEMA, CHIO_FINDING_CHALLENGE_VERIFIER_PROFILE_V1_SCHEMA,
    CHIO_FINDING_FAILED_DELIVERY_V1_SCHEMA, CHIO_FINDING_MARKET_TERMS_V1_SCHEMA,
    CHIO_FINDING_PURCHASE_RECORD_V1_SCHEMA, CHIO_FINDING_SELLER_AUTHORIZATION_V1_SCHEMA,
    CHIO_FINDING_STATUS_EPOCH_V1_SCHEMA, CHIO_FINDING_V1_SCHEMA,
    CHIO_FINDING_VERIFIER_REPORT_V1_SCHEMA, CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_V1_SCHEMA,
    CHIO_FROST_AUTHORIZATION_V1_SCHEMA, CHIO_FROST_EPOCH_CHECKPOINT_V1_SCHEMA,
    CHIO_FROST_ROSTER_V1_SCHEMA, CHIO_OUTCOME_CONTRACTUAL_ZERO_V1_SCHEMA,
    CHIO_OUTCOME_DELIVERY_ACKNOWLEDGEMENT_V1_SCHEMA, CHIO_OUTCOME_DELIVERY_CHECKPOINT_V1_SCHEMA,
    CHIO_OUTCOME_DELIVERY_NONACCEPTANCE_V1_SCHEMA, CHIO_OUTCOME_ELIGIBILITY_V1_SCHEMA,
    CHIO_OUTCOME_OUTPUT_PROVENANCE_V1_SCHEMA, CHIO_OUTCOME_PREDICATE_V1_SCHEMA,
    CHIO_OUTCOME_PRICING_V1_SCHEMA, CHIO_OUTCOME_SLA_V1_SCHEMA,
    CHIO_RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA, CHIO_TRANSACTION_CLAIM_SET_V1_SCHEMA,
    KNOWN_SIGNED_ARTIFACT_SCHEMAS,
};
pub use store_fence::StoreMutationFence;

/// Opaque agent identifier: hex-encoded Ed25519 public key or SPIFFE URI
/// accepted; the core performs no structural validation.
pub type AgentId = alloc::string::String;

/// Opaque tool server identifier.
pub type ServerId = alloc::string::String;

/// UUIDv7 capability identifier (time-ordered).
pub type CapabilityId = alloc::string::String;
