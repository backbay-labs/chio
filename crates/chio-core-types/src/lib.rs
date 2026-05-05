//! Shared Chio substrate types extracted from `chio-core`.
//!
//! This crate holds the protocol-wide types that should remain stable while
//! heavier domain crates split away from the compatibility facade.
//!
//! # no_std support
//!
//! The crate is `no_std + alloc` by source: under `--no-default-features`
//! every module compiles against `core` and `alloc` only. This is the
//! foundation that lets `chio-kernel-core` cross-compile to
//! `wasm32-unknown-unknown` and other embedded targets. The default `std`
//! feature re-enables `std`-backed error impls via `thiserror`, along with
//! the `std` feature on every transitive dependency.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod canonical;
pub mod capability;
pub mod crypto;
pub mod delegation_receipt;
pub mod error;
pub mod hashing;
pub mod loaded_weights;
pub mod manifest;
pub mod merkle;
pub mod message;
pub mod oracle;
pub mod plan;
#[cfg(feature = "pq")]
pub mod pq;
pub mod receipt;
pub mod runtime_attestation;
pub mod session;
pub mod signed_artifact;

pub use canonical::{
    canonical_json_bytes, canonical_json_string, canonicalize, CanonicalBytes, CanonicalJsonWitness,
};
pub use capability::delegate;
pub use capability::{
    canonicalize_attestation_verifier, compute_attenuation_witness, scope_hash,
    validate_attenuation, validate_attenuation_proof, validate_delegation_chain,
    verify_attenuation_witness, Attenuation, AttenuationProof, AttenuationWitness,
    AttestationTrustError, AttestationTrustPolicy, AttestationTrustRule, CapabilityNegotiation,
    CapabilityToken, CapabilityTokenBody, CapabilityTokenSigningBody, CapabilityTokenV2Body,
    Caveat, CaveatKind, ChioScope, Constraint, ContentReviewTier, DelegationLink,
    DelegationLinkBody, GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedAutonomyContext, GovernedAutonomyTier, GovernedCallChainContext,
    GovernedCommerceContext, GovernedTransactionIntent, GrantSubsetRelation, MeteredBillingContext,
    MeteredBillingQuote, MeteredSettlementMode, ModelMetadata, ModelSafetyTier, MonetaryAmount,
    Operation, PromptGrant, ResolvedRuntimeAssurance, ResourceGrant, RuntimeAssuranceTier,
    RuntimeAttestationEvidence, ScopeHash, SqlOperationClass, ToolGrant, WorkloadCredentialKind,
    WorkloadIdentity, WorkloadIdentityError, WorkloadIdentityScheme, CHIO_CAPABILITIES_SCHEMA,
    CHIO_CAPABILITY_V1_SCHEMA, CHIO_CAPABILITY_V2_SCHEMA,
};
pub use crypto::{
    sha256_hex, Ed25519Backend, Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
#[cfg(feature = "pq")]
pub use crypto::{HybridBackend, MlDsa65Backend};
#[cfg(feature = "fips")]
pub use crypto::{P256Backend, P384Backend};
pub use delegation_receipt::{DelegationReceipt, ScopeAttenuation};
pub use error::{Error, Result};
pub use hashing::{sha256, Hash};
pub use loaded_weights::{
    loaded_weights_hash_of, loaded_weights_hash_of_chunks, LoadedWeights, LoadedWeightsUnavailable,
};
pub use manifest::{
    PricingModel, ToolAnnotations, ToolDefinition, ToolManifest, ToolManifestBody, ToolPricing,
};
pub use merkle::{leaf_hash, node_hash, MerkleProof, MerkleTree};
pub use message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
pub use oracle::{OracleConversionEvidence, CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA};
pub use plan::{
    PlanEvaluationRequest, PlanEvaluationResponse, PlanVerdict, PlannedToolCall, PlannedToolCallId,
    StepVerdict, StepVerdictKind,
};
pub use receipt::{
    canonical_parent_receipt_ids, parent_set_hash, receipt_v2_body_hash, verify_receipt_v2_dag,
    ChildRequestReceipt, ChildRequestReceiptBody, ChioReceipt, ChioReceiptBody, ChioReceiptV2,
    Decision, EconomicAmountBoundsReceiptMetadata, EconomicAuthorizationMode,
    EconomicAuthorizationReceiptMetadata, EconomicAuthorizationReceiptMetadataVersion,
    EconomicBudgetReceiptMetadata, EconomicLiabilityReceiptMetadata,
    EconomicMerchantReceiptMetadata, EconomicMeteringReceiptMetadata, EconomicPayeeReceiptMetadata,
    EconomicPayerReceiptMetadata, EconomicPricingBasisReceiptMetadata, EconomicRailReceiptMetadata,
    EconomicSettlementReceiptMetadata, FinancialReceiptMetadata, GovernedApprovalReceiptMetadata,
    GovernedAutonomyReceiptMetadata, GovernedCommerceReceiptMetadata,
    GovernedTransactionReceiptMetadata, GuardEvidence, MeteredBillingReceiptMetadata,
    MeteredUsageEvidenceReceiptMetadata, ReceiptAttributionMetadata, ReceiptDagParent,
    ReceiptHybridLogicalClock, ReceiptLineageStatementV2, ReceiptLineageStatementV2Body,
    ReceiptV2BodyHashInput, ReceiptV2ReplaySet, ReceiptV2SigningBody,
    RuntimeAssuranceReceiptMetadata, SettlementStatus, SignedExportEnvelope, ToolCallAction,
    TrustLevel, CHIO_RECEIPT_LINEAGE_STATEMENT_V2_SCHEMA, CHIO_RECEIPT_V2_SCHEMA,
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
    validate_signed_artifact_schema, SignedArtifactSchemaEntry, CHIO_ANCHOR_BATCH_V1_SCHEMA,
    KNOWN_SIGNED_ARTIFACT_SCHEMAS,
};

/// Opaque agent identifier. In practice this is a hex-encoded Ed25519 public key
/// or a SPIFFE URI, but the core treats it as an opaque string.
pub type AgentId = alloc::string::String;

/// Opaque tool server identifier.
pub type ServerId = alloc::string::String;

/// UUIDv7 capability identifier (time-ordered).
pub type CapabilityId = alloc::string::String;
