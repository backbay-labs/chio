use std::fs::{Metadata, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use rustls::pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest as _, Sha256};
use url::{Host, Url};
use x509_parser::prelude::{FromDer as _, X509Certificate};
use zeroize::Zeroizing;

use crate::HostedEdgeError;

const MAX_TLS_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Paths and policy for the public TLS endpoint: certificate chain,
/// key, optional client CA, and the rotation window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedTlsConfig {
    pub public_endpoint: String,
    pub certificate_chain_path: PathBuf,
    pub private_key_path: PathBuf,
    pub client_ca_path: Option<PathBuf>,
    pub require_client_certificate: bool,
    pub minimum_remaining_validity_secs: u64,
}

impl HostedTlsConfig {
    fn validate(&self) -> Result<(), HostedEdgeError> {
        public_endpoint_server_name(&self.public_endpoint)?;
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

/// Outcome of a reload attempt: swapped or unchanged.
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
    /// Fail closed unless the certificate chain, key, and permissions
    /// validate and the certificate covers the configured host at `now`.
    pub fn load(config: HostedTlsConfig, now: u64) -> Result<Self, HostedEdgeError> {
        config.validate()?;
        let loaded = load_material(&config, now)?;
        Ok(Self {
            config,
            server_config: ArcSwap::from(loaded.server_config),
            metadata: Mutex::new(loaded.metadata),
        })
    }

    /// The current rustls server configuration.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.server_config.load_full()
    }

    /// Re-read the certificate material and swap it in atomically when it
    /// changed and validates.
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

    /// Whether the loaded certificate is valid at `now`.
    #[must_use]
    pub fn ready(&self, now: u64) -> bool {
        self.metadata.lock().is_ok_and(|metadata| {
            now >= metadata.certificate_not_before
                && metadata.certificate_not_after
                    >= now.saturating_add(self.config.minimum_remaining_validity_secs)
        })
    }

    /// Expiry instant of the active certificate.
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
    let certificates = CertificateDer::pem_slice_iter(&certificate_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| HostedEdgeError::Configuration)?;
    if certificates.is_empty() || certificates.len() > 32 {
        return Err(HostedEdgeError::Configuration);
    }
    let private_key = PrivateKeyDer::from_pem_slice(&private_key_bytes)
        .map_err(|_| HostedEdgeError::Configuration)?;
    let server_name = public_endpoint_server_name(&config.public_endpoint)?;
    let (certificate_not_before, certificate_not_after) = validate_server_chain(
        &certificates,
        &server_name,
        now,
        config.minimum_remaining_validity_secs,
    )?;

    let provider: Arc<_> = rustls::crypto::aws_lc_rs::default_provider().into();
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| HostedEdgeError::Configuration)?;
    let mut server_config = if let Some(client_ca_bytes) = client_ca_bytes.as_deref() {
        let mut roots = RootCertStore::empty();
        let client_certificates = CertificateDer::pem_slice_iter(client_ca_bytes)
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

fn validate_server_chain(
    certificates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    now: u64,
    minimum_remaining_validity_secs: u64,
) -> Result<(u64, u64), HostedEdgeError> {
    let parsed = certificates
        .iter()
        .map(|certificate| {
            let (remainder, certificate) = X509Certificate::from_der(certificate.as_ref())
                .map_err(|_| HostedEdgeError::Configuration)?;
            if !remainder.is_empty() {
                return Err(HostedEdgeError::Configuration);
            }
            Ok(certificate)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut chain_not_before = 0_u64;
    let mut chain_not_after = u64::MAX;
    for certificate in &parsed {
        let not_before = u64::try_from(certificate.validity().not_before.timestamp())
            .map_err(|_| HostedEdgeError::Configuration)?;
        let not_after = u64::try_from(certificate.validity().not_after.timestamp())
            .map_err(|_| HostedEdgeError::Configuration)?;
        chain_not_before = chain_not_before.max(not_before);
        chain_not_after = chain_not_after.min(not_after);
    }
    if now < chain_not_before
        || chain_not_after < now.saturating_add(minimum_remaining_validity_secs)
    {
        return Err(HostedEdgeError::Configuration);
    }
    if parsed.len() == 1 {
        let leaf = parsed.first().ok_or(HostedEdgeError::Configuration)?;
        if leaf.subject() != leaf.issuer() || leaf.verify_signature(None).is_err() {
            return Err(HostedEdgeError::Configuration);
        }
    }
    let end_entity = webpki::EndEntityCert::try_from(
        certificates.first().ok_or(HostedEdgeError::Configuration)?,
    )
    .map_err(|_| HostedEdgeError::Configuration)?;
    end_entity
        .verify_is_valid_for_subject_name(server_name)
        .map_err(|_| HostedEdgeError::Configuration)?;
    let trust_anchor = webpki::anchor_from_trusted_cert(
        certificates.last().ok_or(HostedEdgeError::Configuration)?,
    )
    .map_err(|_| HostedEdgeError::Configuration)?;
    let intermediates = if certificates.len() > 2 {
        &certificates[1..certificates.len() - 1]
    } else {
        &[]
    };
    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            std::slice::from_ref(&trust_anchor),
            intermediates,
            UnixTime::since_unix_epoch(Duration::from_secs(now)),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| HostedEdgeError::Configuration)?;
    Ok((chain_not_before, chain_not_after))
}

fn public_endpoint_server_name(value: &str) -> Result<ServerName<'static>, HostedEdgeError> {
    let endpoint = Url::parse(value).map_err(|_| HostedEdgeError::Configuration)?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
        || endpoint.as_str().trim_end_matches('/') != value
    {
        return Err(HostedEdgeError::Configuration);
    }
    match endpoint.host().ok_or(HostedEdgeError::Configuration)? {
        Host::Domain(domain) => {
            ServerName::try_from(domain.to_owned()).map_err(|_| HostedEdgeError::Configuration)
        }
        Host::Ipv4(address) => Ok(ServerName::from(address)),
        Host::Ipv6(address) => Ok(ServerName::from(address)),
    }
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
    use rcgen::{
        generate_simple_self_signed, BasicConstraints, CertificateParams, CertifiedKey, IsCa,
        KeyPair,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> Result<u64, Box<dyn std::error::Error>> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
    }

    #[cfg(unix)]
    fn write_material(directory: &Path) -> Result<HostedTlsConfig, Box<dyn std::error::Error>> {
        write_material_for_endpoint(directory, "market.example", "https://market.example")
    }

    #[cfg(unix)]
    fn write_material_for_endpoint(
        directory: &Path,
        subject_alt_name: &str,
        public_endpoint: &str,
    ) -> Result<HostedTlsConfig, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed([subject_alt_name.to_owned()])?;
        let certificate_path = directory.join("certificate.pem");
        let private_key_path = directory.join("private-key.pem");
        std::fs::write(&certificate_path, cert.pem())?;
        std::fs::write(&private_key_path, key_pair.serialize_pem())?;
        std::fs::set_permissions(&certificate_path, std::fs::Permissions::from_mode(0o644))?;
        std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))?;
        Ok(HostedTlsConfig {
            public_endpoint: public_endpoint.to_owned(),
            certificate_chain_path: certificate_path,
            private_key_path,
            client_ca_path: None,
            require_client_certificate: false,
            minimum_remaining_validity_secs: 300,
        })
    }

    #[cfg(unix)]
    fn write_ca_chain_material(
        directory: &Path,
        include_intermediate: bool,
        expired_intermediate: bool,
    ) -> Result<HostedTlsConfig, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let mut root_params = CertificateParams::new(Vec::<String>::new())?;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_key = KeyPair::generate()?;
        let root = root_params.self_signed(&root_key)?;
        let mut intermediate_params = CertificateParams::new(Vec::<String>::new())?;
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        if expired_intermediate {
            intermediate_params.not_before = rcgen::date_time_ymd(2018, 1, 1);
            intermediate_params.not_after = rcgen::date_time_ymd(2019, 1, 1);
        }
        let intermediate_key = KeyPair::generate()?;
        let intermediate = intermediate_params.signed_by(&intermediate_key, &root, &root_key)?;
        let leaf_params = CertificateParams::new(vec!["market.example".to_owned()])?;
        let leaf_key = KeyPair::generate()?;
        let leaf = leaf_params.signed_by(&leaf_key, &intermediate, &intermediate_key)?;
        let certificate_path = directory.join("certificate-chain.pem");
        let private_key_path = directory.join("private-key.pem");
        let chain = if include_intermediate {
            format!("{}{}{}", leaf.pem(), intermediate.pem(), root.pem())
        } else {
            format!("{}{}", leaf.pem(), root.pem())
        };
        std::fs::write(&certificate_path, chain)?;
        std::fs::write(&private_key_path, leaf_key.serialize_pem())?;
        std::fs::set_permissions(&certificate_path, std::fs::Permissions::from_mode(0o644))?;
        std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))?;
        Ok(HostedTlsConfig {
            public_endpoint: "https://market.example".to_owned(),
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

    #[cfg(unix)]
    #[test]
    fn certificate_must_cover_public_endpoint() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut config = write_material(directory.path())?;
        config.public_endpoint = "https://other.example".to_owned();
        assert!(HostedTlsState::load(config, now()?).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn public_ipv6_endpoint_uses_an_ip_server_name() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let config = write_material_for_endpoint(
            directory.path(),
            "2606:4700:4700::1111",
            "https://[2606:4700:4700::1111]",
        )?;
        assert!(HostedTlsState::load(config, now()?).is_ok());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn complete_presented_certificate_chain_is_validated() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let config = write_ca_chain_material(directory.path(), true, false)?;
        assert!(HostedTlsState::load(config, now()?).is_ok());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn missing_presented_intermediate_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let config = write_ca_chain_material(directory.path(), false, false)?;
        assert!(HostedTlsState::load(config, now()?).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn expired_presented_intermediate_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let config = write_ca_chain_material(directory.path(), true, true)?;
        assert!(HostedTlsState::load(config, now()?).is_err());
        Ok(())
    }
}
