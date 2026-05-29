//! AG-UI Proxy for Chio.
//!
//! This crate intercepts agent-to-UI event streams, validating capability
//! tokens for UI-facing actions and producing receipts that include event
//! type, target component, and action classification.
//!
//! # Transports
//!
//! The proxy supports two transport modes:
//!
//! - **SSE** (Server-Sent Events) -- unidirectional server-to-client stream
//! - **WebSocket** -- bidirectional communication
//!
//! # Architecture
//!
//! ```text
//! Agent -> [AG-UI Proxy] -> UI Client
//!               |
//!          Capability validation
//!          Receipt signing
//!          Event classification
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod event;
pub mod proxy;
pub mod receipt;
pub mod transport;

pub use event::{AgUiEvent, EventClassification, TargetComponent};
pub use proxy::{AgUiProxy, AgUiProxyConfig, ProxyDecision};
pub use receipt::{AgUiReceipt, AgUiReceiptBody, AgUiReceiptVerification};
pub use transport::{Transport, TransportKind};
