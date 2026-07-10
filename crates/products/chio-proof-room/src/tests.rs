use std::{error::Error, fs};

use axum::{
    body::{to_bytes, Body},
    http::{header::CONTENT_TYPE, Request, StatusCode},
};
use chio_core_types::Keypair;
use tower::ServiceExt;

use super::crypto_context::{
    crypto_context_verified_report_bytes, crypto_context_verified_report_bytes_with_bbs,
};
use super::{
    attach_source_runtime_proof_parity_report, build_proof_room_fixture_catalog,
    proof_room_available_fixture_report_from_contents,
    proof_room_router as build_proof_room_router, sha256_hex, validate_proof_room_schema,
    verify_bundle_signature, verify_proof_room_bundle, verify_source_verifier_report,
    verify_transaction_passport_family_report, verify_transaction_passport_file_with_options,
    ProofRoomAvailableFixtureReport, ProofRoomBundleManifest, VerifiedManifestArtifact,
};

mod catalog;
mod core;
mod source;
mod support;
