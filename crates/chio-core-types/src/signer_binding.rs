use alloc::format;

use crate::crypto::{Keypair, PublicKey, SigningBackend};
use crate::error::{Error, Result};

pub(crate) fn ensure_keypair_matches_embedded_key(
    embedded_key: &PublicKey,
    keypair: &Keypair,
    artifact: &str,
    field: &str,
) -> Result<()> {
    ensure_public_key_matches(embedded_key, &keypair.public_key(), artifact, field)
}

pub(crate) fn ensure_backend_matches_embedded_key(
    embedded_key: &PublicKey,
    backend: &dyn SigningBackend,
    artifact: &str,
    field: &str,
) -> Result<()> {
    let actual_key = backend.public_key();
    ensure_public_key_matches(embedded_key, &actual_key, artifact, field)
}

fn ensure_public_key_matches(
    embedded_key: &PublicKey,
    actual_key: &PublicKey,
    artifact: &str,
    field: &str,
) -> Result<()> {
    if embedded_key == actual_key {
        return Ok(());
    }

    Err(Error::InvalidPublicKey(format!(
        "{artifact} {field} does not match signing key"
    )))
}
