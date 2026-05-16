//! Live Chiodos pheromone relay service and durable relay state.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::{Keypair, PublicKey, Signature};
use chio_federation::PheromoneGossipBatch;
use chio_pheromone_runtime::PheromoneReceiveReport;
use rusqlite::{params, Connection};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

mod alerts;
mod archive;
mod assurance;
mod client;
mod delivery;
mod directory;
mod error;
mod http_signing;
mod metrics;
mod schema;
mod service;
mod store;
mod validation;

pub use alerts::*;
pub use archive::*;
pub use assurance::*;
pub use client::*;
pub use delivery::*;
pub use directory::*;
pub use error::*;
pub use http_signing::*;
pub use metrics::*;
pub use schema::*;
pub use service::*;
pub use store::*;
pub(crate) use validation::*;
