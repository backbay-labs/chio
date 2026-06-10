#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "relay/common.rs"]
mod common;

#[path = "relay/alerts.rs"]
mod alerts;
#[path = "relay/archive.rs"]
mod archive;
#[path = "relay/delivery.rs"]
mod delivery;
#[path = "relay/directory.rs"]
mod directory;
#[path = "relay/observability.rs"]
mod observability;
#[path = "relay/service.rs"]
mod service;
