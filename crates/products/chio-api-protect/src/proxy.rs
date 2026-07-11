//! Reverse proxy server that evaluates requests and forwards to upstream.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Json;
use axum::Router;
use chio_http_serve::{CappedPeerAddr, MaxConnListener};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::{info, warn};

use chio_core_types::capability::{
    governance::{GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody},
    scope::{ChioScope, Operation, PromptGrant, ResourceGrant, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::BoundaryClass, kinds::ObservationOutcome, kinds::ReceiptKind, kinds::RedactionMode,
    kinds::ToolOrigin, kinds::TrustLevel,
};
use chio_http_core::{
    client_builder_with_contract, handle_batch_respond, handle_get_approval, handle_list_pending,
    handle_respond, http_status_metadata_decision, http_status_metadata_final, send_with_contract,
    ApprovalAdmin, ApprovalHandlerError, BatchRespondRequest, CallerIdentity, ChioHttpRequest,
    EvaluateResponse, HealthResponse, HttpEgressContract, HttpMethod, HttpReceipt, HttpReceiptBody,
    PendingQuery, RespondRequest, SidecarStatus, Verdict, VerifyReceiptResponse,
};
use chio_kernel::{ApprovalOutcome, ApprovalRequest, ApprovalStore, InMemoryApprovalStore};
use chio_openapi::{ChioExtensions, DefaultPolicy};
use chio_store_sqlite::SqliteApprovalStore;

use crate::error::ProtectError;
use crate::evaluator::{RequestEvaluator, RouteEntry};
use crate::spec_discovery::{default_upstream_egress_contract, discover_spec, load_spec_from_file};

#[path = "proxy/approval.rs"]
mod approval;
#[path = "proxy/attenuation.rs"]
mod attenuation;
#[path = "proxy/config.rs"]
mod config;
#[path = "proxy/decision.rs"]
mod decision;
#[path = "proxy/errors.rs"]
mod errors;
#[path = "proxy/http.rs"]
mod http;
#[path = "proxy/receipts.rs"]
mod receipts;
#[path = "proxy/router.rs"]
mod router;
#[path = "proxy/scope_subset.rs"]
mod scope_subset;
#[path = "proxy/sidecar.rs"]
mod sidecar;
#[path = "proxy/state.rs"]
mod state;

pub(crate) use self::approval::*;
pub(crate) use self::attenuation::*;
pub(crate) use self::decision::*;
pub(crate) use self::errors::*;
pub(crate) use self::http::*;
pub(crate) use self::receipts::*;
pub(crate) use self::router::*;
pub(crate) use self::scope_subset::*;
pub(crate) use self::sidecar::*;
pub(crate) use self::state::*;

pub use self::config::{ProtectConfig, DEFAULT_UPSTREAM_REQUEST_TIMEOUT};
pub use self::state::ProtectProxy;

#[cfg(test)]
#[path = "proxy/nonce_tests.rs"]
mod nonce_tests;

#[cfg(test)]
#[path = "proxy/tests.rs"]
mod tests;
