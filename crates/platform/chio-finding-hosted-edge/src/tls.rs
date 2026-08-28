use std::fs::{Metadata, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest as _, Sha256};
use x509_parser::prelude::{FromDer as _, X509Certificate};
use zeroize::Zeroizing;

use crate::HostedEdgeError;

const MAX_TLS_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedTlsConfig {
    pub certificate_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub client_ca_path: Option<PathBuf>,
    pub require_client_certificate: bool,
    pub minimum_remaining_validity_secs: u64,
}

impl HostedTlsConfig {
    fn validate(&self) -> Result<(), HostedEdgeError> {
        for path in [
            Some(self.certificate_chain_path.as_path()),
            Some(self.private_key_path.as_path()),
            self.client_ca_path.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            {
                return Err(HostedEdgeError::Configuration);
            }
        }
        if self.require_client_certificate != self.client_ca_path.is_some()
            || !(300..=2_592_000).contains(&self.minimum_remaining_validity_secs)
        {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedTlsReload {
    Applied,
    Unchanged,
}

#[derive(Clone, Debug)]
struct TlsMetadata {
    material_sha256: String,
    certificate_not_before: u64,
    certificate_not_after: u64,
}

struct LoadedTlsMaterial {
    server_config: Arc<ServerConfig>,
    metadata: TlsMetadata,
}

/// TLS 1.3 server material with atomic, last-known-good hot reload.
pub struct HostedTlsState {
    config: HostedTlsConfig,
    server_config: ArcSwap<ServerConfig>,
    metadata: Mutex<TlsMetadata>,
}

impl HostedTlsState {
    pub fn load(config: HostedTlsConfig, now: u64) -> Result<Self, HostedEdgeError> {
        config.validate()?;
        let loaded = load_material(&config, now)?;
        Ok(Self {
            config,
            server_config: ArcSwap::from(loaded.server_config),
            metadata: Mutex::new(loaded.metadata),
        })
    }

    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.server_config.load_full()
    }

    pub fn reload(&self, now: u64) -> Result<HostedTlsReload, HostedEdgeError> {
        let loaded = load_material(&self.config, now)?;
        let mut metadata = self
            .metadata
            .lock()
            .map_err(|_| HostedEdgeError::DependencyUnavailable)?;
        if metadata.material_sha256 == loaded.metadata.material_sha256 {
            return Ok(HostedTlsReload::Unchanged);
        }
        self.server_config.store(loaded.server_config);
        *metadata = loaded.metadata;
        Ok(HostedTlsReload::Applied)
    }

    #[must_use]
    pub fn ready(&self, now: u64) -> bool {
        self.metadata.lock().is_ok_and(|metadata| {
            now >= metadata.certificate_not_before
                && metadata.certificate_not_after
                    >= now.saturating_add(self.config.minimum_remaining_validity_secs)
        })
    }

    pub fn certificate_not_after(&self) -> Result<u64, HostedEdgeError> {
        self.metadata
            .lock()
            .map(|metadata| metadata.certificate_not_after)
            .map_err(|_| HostedEdgeError::DependencyUnavailable)
    }
}

fn load_material(config: &HostedTlsConfig, now: u64) -> Result<LoadedTlsMaterial, HostedEdgeError> {
    if now == 0 {
        return Err(HostedEdgeError::Configuration);
    }
    let certificate_bytes = read_regular(&config.certificate_chain_path, false)?;
    let private_key_bytes = Zeroizing::new(read_regular(&config.private_key_path, true)?);
    let client_ca_bytes = config
        .client_ca_path
        .as_deref()
        .map(|path| read_regular(path, false))
        .transpose()?;
    let certificates = rustls_pemfile::certs(&mut certificate_bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| HostedEdgeError::Configuration)?;
    if certificates.is_empty() || certificates.len() > 32 {
        return Err(HostedEdgeError::Configuration);
    }
    let private_key = rustls_pemfile::private_key(&mut private_key_bytes.as_slice())
        .map_err(|_| HostedEdgeError::Configuration)?
        .ok_or(HostedEdgeError::Configuration)?;
    let (_, leaf) = X509Certificate::from_der(certificates[0].as_ref())
        .map_err(|_| HostedEdgeError::Configuration)?;
    let certificate_not_before = u64::try_from(leaf.validity().not_before.timestamp())
        .map_err(|_| HostedEdgeError::Configuration)?;
    let certificate_not_after = u64::try_from(leaf.validity().not_after.timestamp())
        .map_err(|_| HostedEdgeError::Configuration)?;
    if now < certificate_not_before
        || certificate_not_after < now.saturating_add(config.minimum_remaining_validity_secs)
    {
        return Err(HostedEdgeError::Configuration);
    }

    let provider: Arc<_> = rustls::crypto::aws_lc_rs::default_provider().into();
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| HostedEdgeError::Configuration)?;
    let mut server_config = if let Some(client_ca_bytes) = client_ca_bytes.as_deref() {
        let mut roots = RootCertStore::empty();
        let mut client_ca_reader = client_ca_bytes;
        let client_certificates = rustls_pemfile::certs(&mut client_ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HostedEdgeError::Configuration)?;
        if client_certificates.is_empty() || client_certificates.len() > 64 {
            return Err(HostedEdgeError::Configuration);
        }
        for certificate in client_certificates {
            roots
                .add(certificate)
                .map_err(|_| HostedEdgeError::Configuration)?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|_| HostedEdgeError::Configuration)?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, private_key)
            .map_err(|_| HostedEdgeError::Configuration)?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|_| HostedEdgeError::Configuration)?
    };
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut material_hasher = Sha256::new();
    material_hasher.update(&certificate_bytes);
    material_hasher.update(private_key_bytes.as_slice());
    if let Some(client_ca_bytes) = client_ca_bytes {
        material_hasher.update(&client_ca_bytes);
    }
    Ok(LoadedTlsMaterial {
        server_config: Arc::new(server_config),
        metadata: TlsMetadata {
            material_sha256: hex::encode(material_hasher.finalize()),
            certificate_not_before,
            certificate_not_after,
        },
    })
}

fn read_regular(path: &Path, private: bool) -> Result<Vec<u8>, HostedEdgeError> {
    let before = std::fs::symlink_metadata(path).map_err(|_| HostedEdgeError::Configuration)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > MAX_TLS_FILE_BYTES
    {
        return Err(HostedEdgeError::Configuration);
    }
    validate_permissions(&before, private)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| HostedEdgeError::Configuration)?;
    let after = file
        .metadata()
        .map_err(|_| HostedEdgeError::Configuration)?;
    if !same_file(&before, &after) {
        return Err(HostedEdgeError::Configuration);
    }
    let mut bytes = Vec::with_capacity(after.len() as usize);
    file.by_ref()
        .take(MAX_TLS_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| HostedEdgeError::Configuration)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_TLS_FILE_BYTES {
        return Err(HostedEdgeError::Configuration);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_permissions(metadata: &Metadata, private: bool) -> Result<(), HostedEdgeError> {
    use std::os::unix::fs::MetadataExt as _;
    let forbidden = if private { 0o077 } else { 0o022 };
    if metadata.mode() & forbidden != 0 {
        return Err(HostedEdgeError::Configuration);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_permissions(_metadata: &Metadata, _private: bool) -> Result<(), HostedEdgeError> {
    Ok(())
}

#[cfg(unix)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(not(unix))]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.len() == after.len()
        && before.modified().ok().is_some()
        && before.modified().ok() == after.modified().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> Result<u64, Box<dyn std::error::Error>> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
    }

    #[cfg(unix)]
    fn write_material(directory: &Path) -> Result<HostedTlsConfig, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(["market.example".to_owned()])?;
        let certificate_path = directory.join("certificate.pem");
        let private_key_path = directory.join("private-key.pem");
        std::fs::write(&certificate_path, cert.pem())?;
        std::fs::write(&private_key_path, key_pair.serialize_pem())?;
        std::fs::set_permissions(&certificate_path, std::fs::Permissions::from_mode(0o644))?;
        std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))?;
        Ok(HostedTlsConfig {
            certificate_chain_path: certificate_path,
            private_key_path,
            client_ca_path: None,
            require_client_certificate: false,
            minimum_remaining_validity_secs: 300,
        })
    }

    #[cfg(unix)]
    #[test]
    fn invalid_reload_retains_last_known_good_configuration(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let config = write_material(directory.path())?;
        let now = now()?;
        let state = HostedTlsState::load(config.clone(), now)?;
        let original = state.server_config();
        std::fs::write(&config.private_key_path, b"not a key")?;
        assert!(state.reload(now).is_err());
        assert!(Arc::ptr_eq(&original, &state.server_config()));
        assert!(state.ready(now));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_private_key_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let config = write_material(directory.path())?;
        std::fs::set_permissions(
            &config.private_key_path,
            std::fs::Permissions::from_mode(0o640),
        )?;
        let now = now()?;
        assert!(HostedTlsState::load(config, now).is_err());
        Ok(())
    }
}
