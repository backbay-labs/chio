use std::fs;
use std::path::Path;

use chio_store_sqlite::{SqliteEncryptedBlobStore, TenantId, TenantKey};
use chio_tee::{TeeBlobPersistence, TeeBlobSpool};

const OPENAI_SINGLE_TOOL: &[u8] =
    include_bytes!("../../chio-tool-call-fabric/fixtures/lift_lower/openai/single_tool.json");
const ANTHROPIC_SERVER_TOOL: &[u8] =
    include_bytes!("../../chio-tool-call-fabric/fixtures/lift_lower/anthropic/server_tool.json");
const BEDROCK_ASSUMED_ROLE: &[u8] =
    include_bytes!("../../chio-tool-call-fabric/fixtures/lift_lower/bedrock/assumed_role.json");

fn sqlite_bytes(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let candidate = Path::new(&format!("{}{}", path.display(), suffix)).to_path_buf();
        if candidate.exists() {
            bytes.extend(fs::read(candidate)?);
        }
    }
    Ok(bytes)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

#[test]
fn spool_persists_m07_fixture_payloads_encrypted_at_rest() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("tee-spool.sqlite3");
    let store = SqliteEncryptedBlobStore::open(&db_path)?;
    let spool = TeeBlobSpool::new(TeeBlobPersistence::new(store));
    let tenant = TenantId::new("tenant-m07-fixtures");
    let key = TenantKey::from_bytes([7; 32]);

    let traffic =
        spool.persist_traffic(&tenant, &key, OPENAI_SINGLE_TOOL, ANTHROPIC_SERVER_TOOL)?;
    let request = spool.read_blob(&traffic.request.handle, &key)?;
    let response = spool.read_blob(&traffic.response.handle, &key)?;

    assert_eq!(request, OPENAI_SINGLE_TOOL);
    assert_eq!(response, ANTHROPIC_SERVER_TOOL);
    assert_eq!(traffic.request.plaintext_len, OPENAI_SINGLE_TOOL.len());
    assert_eq!(traffic.response.plaintext_len, ANTHROPIC_SERVER_TOOL.len());

    let encrypted_request = spool.load_encrypted_blob(&traffic.request.handle)?;
    let encrypted_response = spool.load_encrypted_blob(&traffic.response.handle)?;
    assert_ne!(encrypted_request.ciphertext, OPENAI_SINGLE_TOOL);
    assert_ne!(encrypted_response.ciphertext, ANTHROPIC_SERVER_TOOL);
    assert_ne!(encrypted_request.nonce, encrypted_response.nonce);

    let raw_sqlite = sqlite_bytes(&db_path)?;
    assert!(!contains(&raw_sqlite, b"resp_2026_04_25_single_tool"));
    assert!(!contains(&raw_sqlite, b"msg_03poiuYTREWQasdfghjklm"));

    let wrong_key = TenantKey::from_bytes([8; 32]);
    let wrong_key_error = spool.read_blob(&traffic.request.handle, &wrong_key);
    assert!(wrong_key_error.is_err());

    Ok(())
}

#[test]
fn spool_keeps_multiple_provider_fixtures_tenant_scoped() -> Result<(), Box<dyn std::error::Error>>
{
    let store = SqliteEncryptedBlobStore::open_in_memory()?;
    let spool = TeeBlobSpool::new(TeeBlobPersistence::new(store));
    let tenant = TenantId::new("tenant-m07-bedrock");
    let key = TenantKey::from_bytes([11; 32]);

    let traffic = spool.persist_traffic(&tenant, &key, BEDROCK_ASSUMED_ROLE, OPENAI_SINGLE_TOOL)?;

    assert_eq!(
        traffic.request.handle.tenant_id().as_str(),
        "tenant-m07-bedrock"
    );
    assert_eq!(
        spool.read_blob(&traffic.request.handle, &key)?,
        BEDROCK_ASSUMED_ROLE
    );
    assert_eq!(
        spool.read_blob(&traffic.response.handle, &key)?,
        OPENAI_SINGLE_TOOL
    );

    Ok(())
}
