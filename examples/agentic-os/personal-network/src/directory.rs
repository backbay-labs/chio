use anyhow::{Context, Result};
use chio_agent_os_shared::{
    events::now_ms,
    graph::digest,
    host::{private_directory, write_json},
    json,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_federation_transport_iroh::{admission::DirectoryGate, identity::*};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
#[derive(Clone, Serialize, Deserialize)]
pub struct Enrollment {
    pub entry: TransportDirectoryEntry,
    pub address: iroh::EndpointAddr,
    pub http_url: String,
    pub pid: u32,
    pub kernel_key: PublicKey,
}
pub fn key(path: &Path) -> Result<Keypair> {
    if path.exists() {
        return Ok(Keypair::from_seed_hex(
            std::fs::read_to_string(path)?.trim(),
        )?);
    }
    let key = Keypair::generate();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut file = options.open(path)?;
    file.write_all(key.seed_hex().as_bytes())?;
    file.sync_all()?;
    Ok(key)
}
pub fn bundle(
    issuer: &Keypair,
    local: &str,
    entries: Vec<TransportDirectoryEntry>,
    version: u64,
    previous: Option<String>,
    expires: u64,
) -> Result<TransportDirectoryBundleDocument> {
    let directory = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.into(),
        local_kernel_id: local.into(),
        treaties: vec![TransportTreatyEntry {
            treaty_id: super::wire::TREATY.into(),
            party_kernel_ids: entries
                .iter()
                .filter(|e| !e.removed)
                .map(|e| e.kernel_id.clone())
                .collect(),
        }],
        peers: entries,
    };
    let body = TransportDirectoryBundleBody {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.into(),
        issuer: "did:chio:personal-directory".into(),
        key_id: "directory-owner".into(),
        directory_sha256: digest(&directory)?,
        version,
        previous_version_sha256: previous,
        issued_at_unix_ms: now_ms().saturating_sub(1),
        expires_at_unix_ms: expires,
    };
    let (signature, _) = issuer.sign_canonical(&body)?;
    Ok(TransportDirectoryBundleDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.into(),
        body,
        directory,
        signature,
    })
}
pub struct Directory {
    pub gate: DirectoryGate,
    root: PathBuf,
    issuer: PublicKey,
    local: String,
    update: Mutex<()>,
}
impl Directory {
    pub fn open(root: &Path, issuer: PublicKey, local: String) -> Result<Self> {
        private_directory(root)?;
        let this = Self {
            gate: DirectoryGate::new(Arc::new(VerifiedDirectory::empty_deny_all())),
            root: root.into(),
            issuer,
            local,
            update: Mutex::new(()),
        };
        let file = root.join("directory.json");
        if file.exists() {
            let bundle: TransportDirectoryBundleDocument =
                serde_json::from_slice(&std::fs::read(file)?)?;
            let head: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join("directory-head.json"))?)?;
            anyhow::ensure!(
                head["version"] == bundle.body.version
                    && head["body_sha256"] == digest(&bundle.body)?,
                "Directory and retained version do not match; inspect an interrupted update"
            );
            // Startup verifies the exact retained bundle, including time and signer.
            // Expiration leaves the gate closed until a fresh successor arrives.
            if bundle.body.expires_at_unix_ms > now_ms() {
                let verified = this.verify(&bundle, bundle.body.version.saturating_sub(1), None)?;
                this.gate.swap(Arc::new(verified));
            }
        }
        Ok(this)
    }
    fn verify(
        &self,
        bundle: &TransportDirectoryBundleDocument,
        floor: u64,
        previous: Option<String>,
    ) -> Result<VerifiedDirectory> {
        anyhow::ensure!(
            bundle.directory.local_kernel_id == self.local,
            "Directory belongs to another node"
        );
        Ok(bundle.verify_bundle(&TransportDirectoryBundleTrust {
            issuers: vec![TrustedTransportDirectoryIssuer {
                issuer: "did:chio:personal-directory".into(),
                key_id: "directory-owner".into(),
                public_key: self.issuer.clone(),
            }],
            version_floor: floor,
            expected_previous_version_sha256: previous,
            now_unix_ms: now_ms(),
        })?)
    }
    pub fn update(&self, bundle: TransportDirectoryBundleDocument) -> Result<u64> {
        let _lock = self
            .update
            .lock()
            .map_err(|_| anyhow::anyhow!("Directory update lock failed"))?;
        let headfile = self.root.join("directory-head.json");
        let (floor, previous) = if headfile.exists() {
            let head: serde_json::Value = serde_json::from_slice(&std::fs::read(headfile)?)?;
            (
                head["version"]
                    .as_u64()
                    .context("Invalid directory version")?,
                Some(
                    head["body_sha256"]
                        .as_str()
                        .context("Missing directory digest")?
                        .to_string(),
                ),
            )
        } else {
            (0, None)
        };
        let verified = self.verify(&bundle, floor, previous)?;
        write_json(&self.root.join("directory.json"), &json!(bundle))?;
        write_json(
            &self.root.join("directory-head.json"),
            &json!({"version":bundle.body.version,"body_sha256":digest(&bundle.body)?}),
        )?;
        self.gate.swap(Arc::new(verified));
        Ok(bundle.body.version)
    }
    pub fn live(&self) -> Result<()> {
        anyhow::ensure!(
            self.gate.current_expires_at_unix_ms() > now_ms(),
            "Directory expired; install a signed successor"
        );
        Ok(())
    }
}
