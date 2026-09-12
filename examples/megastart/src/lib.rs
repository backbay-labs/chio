pub mod authority;
pub mod mission;
pub mod operations;
pub mod protocol;

use anyhow::{Context, Result};
use chio_agent_os_shared::runtime::files;
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

pub fn digest(value: &impl Serialize) -> Result<String> {
    Ok(chio_core::sha256_hex(&chio_core::canonical_json_bytes(
        value,
    )?))
}

pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        files::read_text(path, 2_000_000).with_context(|| format!("Read {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn retain(path: &Path, value: &impl Serialize) -> Result<()> {
    files::create(path, &serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub mod journal;
pub mod model;
pub mod operator;
pub mod sandbox;
