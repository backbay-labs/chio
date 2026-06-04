//! Chio adapter for Envoy's [`ext_authz`][ext-authz] gRPC filter.
//!
//! This crate implements `envoy.service.auth.v3.Authorization/Check` as a thin
//! shim that translates each Envoy `CheckRequest` into a Chio
//! [`translate::ToolCallRequest`], hands it to an [`EnvoyKernel`] implementation,
//! and maps the returned [`translate::Verdict`] onto a compliant
//! `CheckResponse`.
//!
//! The crate deliberately keeps its dependency surface small so the adapter
//! can be linked into any Envoy-fronted service without pulling in the rest
//! of the Chio substrate. The [`EnvoyKernel`] trait exists precisely so real
//! deployments can plug `chio-kernel` (or `chio-http-core`'s `HttpAuthority`)
//! into this service without this crate depending on them.
//!
//! # Example wiring
//!
//! ```ignore
//! use chio_envoy_ext_authz::{
//!     proto::envoy::service::auth::v3::authorization_server::AuthorizationServer,
//!     translate::{ToolCallRequest, Verdict},
//!     ChioExtAuthzService, EnvoyKernel, KernelError,
//! };
//! use async_trait::async_trait;
//!
//! struct MyKernel;
//!
//! #[async_trait]
//! impl EnvoyKernel for MyKernel {
//!     async fn evaluate(
//!         &self,
//!         request: ToolCallRequest,
//!     ) -> Result<Verdict, KernelError> {
//!         // Delegate to chio-kernel / HttpAuthority / custom policy here.
//!         Ok(Verdict::Allow)
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let svc = ChioExtAuthzService::new(MyKernel);
//!     tonic::transport::Server::builder()
//!         .add_service(AuthorizationServer::new(svc))
//!         .serve("0.0.0.0:9091".parse()?)
//!         .await?;
//!     Ok(())
//! }
//! ```
//!
//! [ext-authz]: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod service;
pub mod translate;

mod metadata;
mod response;

pub use error::{KernelError, TranslateError};
pub use service::{ChioExtAuthzService, EnvoyKernel};
pub use translate::{
    check_request_to_tool_call, AuthMethod, CallerIdentity, HttpMethod, ToolCallRequest, Verdict,
    ENVOY_SERVER_ID,
};

/// Generated protobuf bindings for the vendored Envoy ext_authz v3 service.
///
/// The module tree mirrors the `.proto` package hierarchy so downstream code
/// can address each message by its fully qualified protobuf name.
pub mod proto {
    /// Envoy API protobuf modules. Only the messages required by ext_authz
    /// are vendored; see each `.proto` for the upstream source.
    pub mod envoy {
        /// `envoy.service` generated modules.
        pub mod service {
            /// `envoy.service.auth` generated modules.
            pub mod auth {
                /// `envoy.service.auth.v3` generated module.
                pub mod v3 {
                    #![allow(missing_docs)]
                    tonic::include_proto!("envoy.service.auth.v3");
                }
            }
        }

        /// `envoy.config` generated modules.
        pub mod config {
            /// `envoy.config.core` generated modules.
            pub mod core {
                /// `envoy.config.core.v3` generated module.
                pub mod v3 {
                    #![allow(missing_docs)]
                    tonic::include_proto!("envoy.config.core.v3");
                }
            }
        }

        /// `envoy.type` generated modules. The `type` module name is escaped
        /// because `type` is a Rust keyword.
        pub mod r#type {
            /// `envoy.type.v3` generated module.
            pub mod v3 {
                #![allow(missing_docs)]
                tonic::include_proto!("envoy.r#type.v3");
            }
        }
    }

    /// `google.rpc` generated modules.
    pub mod google {
        /// `google.rpc` generated module.
        pub mod rpc {
            #![allow(missing_docs)]
            tonic::include_proto!("google.rpc");
        }
    }
}
