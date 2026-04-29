//! Signed audit entries for TEE capture blessing.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chio_core::{canonical_json_bytes, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Event name pinned by the M10 bless-graduation runbook.
pub const TEE_BLESS_EVENT: &str = "tee.bless";
/// Capability required by `chio replay --bless`.
pub const TEE_BLESS_CAPABILITY: &str = "chio:tee/bless@1";

const ED25519_SIGNATURE_PREFIX: &str = "ed25519:";

/// Operator identity recorded for a bless event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlessOperator {
    /// Operator DID, normally a `did:web` identity.
    pub id: String,
    /// Git identity observed by the bless command.
    pub git_user: String,
}

/// Source capture counts recorded for a bless event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlessCapture {
    /// Capture path as recorded by the operator.
    pub path: String,
    /// Frames read before dedupe.
    pub frames_in: usize,
    /// Frames retained after canonical-invocation last-wins dedupe.
    pub frames_after_dedupe: usize,
    /// Frames retained after current default redaction.
    pub frames_after_redact: usize,
}

/// Fixture identity recorded for a bless event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlessFixture {
    /// M04 fixture family.
    pub family: String,
    /// M04 fixture scenario name.
    pub name: String,
    /// Fixture path as recorded by the operator.
    pub path: String,
    /// Merkle root written to `root.hex`.
    pub receipts_root: String,
}

/// Signature body for a `tee.bless` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeeBlessAuditBody {
    /// Pinned event name.
    pub event: String,
    /// RFC3339 UTC event timestamp.
    pub ts: String,
    /// Human operator identity.
    pub operator: BlessOperator,
    /// Source capture details.
    pub capture: BlessCapture,
    /// Graduated M04 fixture details.
    pub fixture: BlessFixture,
    /// Redaction pass used for the blessed fixture.
    pub redaction_pass_id: String,
    /// Capability that authorized the bless operation.
    pub control_plane_capability: String,
}

impl TeeBlessAuditBody {
    /// Build the canonical body for a `tee.bless` audit event.
    pub fn new(
        ts: impl Into<String>,
        operator: BlessOperator,
        capture: BlessCapture,
        fixture: BlessFixture,
        redaction_pass_id: impl Into<String>,
    ) -> Self {
        Self {
            event: TEE_BLESS_EVENT.to_string(),
            ts: ts.into(),
            operator,
            capture,
            fixture,
            redaction_pass_id: redaction_pass_id.into(),
            control_plane_capability: TEE_BLESS_CAPABILITY.to_string(),
        }
    }
}

/// Signed `tee.bless` event as persisted to the receipt store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeeBlessAuditEntry {
    /// Body fields are top-level in the wire JSON.
    #[serde(flatten)]
    pub body: TeeBlessAuditBody,
    /// Ed25519 signature over the canonical JSON body.
    pub signature: String,
}

impl TeeBlessAuditEntry {
    /// Sign a `tee.bless` body with an Ed25519 operator key.
    pub fn sign(body: TeeBlessAuditBody, keypair: &Keypair) -> Result<Self, BlessAuditError> {
        let (signature, _) = keypair.sign_canonical(&body)?;
        Ok(Self {
            body,
            signature: format!("{ED25519_SIGNATURE_PREFIX}{}", signature.to_hex()),
        })
    }

    /// Verify this event's signature against the supplied operator key.
    pub fn verify_signature(&self, public_key: &PublicKey) -> Result<bool, BlessAuditError> {
        let Some(signature_hex) = self.signature.strip_prefix(ED25519_SIGNATURE_PREFIX) else {
            return Err(BlessAuditError::InvalidSignaturePrefix(
                self.signature.clone(),
            ));
        };
        let signature = Signature::from_hex(signature_hex)?;
        Ok(public_key.verify_canonical(&self.body, &signature)?)
    }

    /// Canonical JSON bytes for receipt-store persistence.
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, BlessAuditError> {
        Ok(canonical_json_bytes(self)?)
    }
}

/// Append a signed `tee.bless` event to the receipt-store JSONL path.
pub fn write_tee_bless_audit_entry(
    path: impl AsRef<Path>,
    entry: &TeeBlessAuditEntry,
) -> Result<(), BlessAuditError> {
    let path = path.as_ref();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| BlessAuditError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| BlessAuditError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let bytes = entry.canonical_json_bytes()?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|source| BlessAuditError::Io {
            path: path.to_path_buf(),
            source,
        })
}

/// Errors emitted by bless audit helpers.
#[derive(Debug, Error)]
pub enum BlessAuditError {
    /// Signature did not use the required `ed25519:<hex>` envelope.
    #[error("tee.bless signature must use ed25519:<hex> form, got {0}")]
    InvalidSignaturePrefix(String),
    /// Canonical JSON, signing, or signature decoding failed.
    #[error("core signing/canonical JSON failed: {0}")]
    Core(#[from] chio_core::Error),
    /// Receipt-store append failed.
    #[error("audit log I/O error at {path}: {source}")]
    Io {
        /// Path being operated on.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}
