//! Session-scoped identifiers and normalized operations.
//!
//! These types sit above the raw transport frames. The edge layer can translate
//! JSON-RPC, stdio frames, or another protocol into `SessionOperation`, and the
//! kernel can evaluate those operations without knowing how they arrived.

mod anchor;
mod auth;
mod identifiers;
mod lineage;
mod messages;
mod normalization;
mod operation;
mod ownership;
mod payloads;
mod resources;
mod session_op;

pub use self::anchor::{
    SessionAnchor, SessionAnchorBody, SessionAnchorContext, SessionAnchorReference,
    SessionProofBinding, CHIO_SESSION_ANCHOR_SCHEMA,
};
pub use self::auth::{
    ChioIdentityAssertion, EnterpriseFederationMethod, EnterpriseIdentityContext,
    OAuthBearerFederatedClaims, OAuthBearerSessionAuthInput, SessionAuthContext, SessionAuthMethod,
};
pub use self::identifiers::{ProgressToken, RequestId, SessionId};
pub use self::lineage::{
    RequestLineageMode, RequestLineageRecord, CHIO_REQUEST_LINEAGE_RECORD_SCHEMA,
};
pub use self::messages::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, ElicitationAction,
};
pub use self::normalization::{NormalizedRoot, ResourceUriClassification, RootDefinition};
pub use self::operation::{OperationContext, OperationKind, OperationTerminalState};
pub use self::ownership::{
    RequestOwnershipSnapshot, SessionTransport, StreamOwner, TaskOwnershipSnapshot, WorkOwner,
};
pub use self::payloads::{CompleteOperation, GetPromptOperation, ReadResourceOperation};
pub use self::resources::{
    CompletionArgument, CompletionReference, CompletionResult, PromptArgument, PromptDefinition,
    PromptMessage, PromptResult, ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
    SamplingMessage, SamplingTool, SamplingToolChoice, ToolCallOperation,
};
pub use self::session_op::SessionOperation;

#[cfg(test)]
use self::normalization::{
    extract_uri_scheme, normalize_absolute_filesystem_path, split_windows_drive,
};
#[cfg(test)]
use crate::capability::{
    governance::ProvenanceEvidenceClass, scope::ModelMetadata, token::CapabilityToken,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
