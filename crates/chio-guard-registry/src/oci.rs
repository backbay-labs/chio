//! OCI distribution primitives for Chio guard artifacts.

use std::convert::TryFrom;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use oci_distribution::client::{ClientConfig, ClientProtocol, Config, ImageData, ImageLayer};
use oci_distribution::errors::OciDistributionError;
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::{Client, ParseError, Reference};

/// OCI artifact media type for a Chio guard bundle.
pub const GUARD_ARTIFACT_MEDIA_TYPE: &str = "application/vnd.chio.guard.v2+wasm";
/// OCI config media type for guard runtime metadata.
pub const GUARD_CONFIG_MEDIA_TYPE: &str = "application/vnd.chio.guard.config.v2+json";
/// WIT contract layer media type.
pub const GUARD_WIT_LAYER_MEDIA_TYPE: &str = "application/vnd.chio.guard.wit.v2";
/// Wasm component layer media type.
pub const GUARD_MODULE_LAYER_MEDIA_TYPE: &str = "application/vnd.chio.guard.module.v2+wasm";
/// Chio guard manifest layer media type.
pub const GUARD_MANIFEST_LAYER_MEDIA_TYPE: &str = "application/vnd.chio.guard.manifest.v2+json";
/// Annotation role for the WIT layer.
pub const GUARD_WIT_LAYER_ROLE: &str = "wit";
/// Annotation role for the wasm layer.
pub const GUARD_MODULE_LAYER_ROLE: &str = "wasm";
/// Annotation role for the manifest layer.
pub const GUARD_MANIFEST_LAYER_ROLE: &str = "manifest";

pub(crate) const OCI_SCHEME: &str = "oci://";
const SHA256_PREFIX: &str = "sha256:";
const SHA256_HEX_LEN: usize = 64;

/// Result type for guard registry operations.
pub type Result<T> = std::result::Result<T, GuardRegistryError>;

/// Errors returned by the guard registry scaffold.
#[derive(Debug, thiserror::Error)]
pub enum GuardRegistryError {
    /// The user provided a reference without the required `oci://` prefix.
    #[error("guard OCI reference must start with oci://")]
    MissingOciScheme,

    /// The reference would fall back to Docker Hub or another implicit registry.
    #[error("guard OCI reference must include an explicit registry")]
    MissingRegistry,

    /// The reference was not pinned by digest.
    #[error("guard OCI reference must be pinned by sha256 digest")]
    MissingDigest,

    /// The reference had a tag in addition to a digest.
    #[error("guard OCI reference must not include a tag when pinned by digest")]
    TaggedDigestReference,

    /// The digest was not a lower-case sha256 digest.
    #[error("guard OCI digest must be sha256 followed by 64 lower-case hex characters")]
    InvalidSha256Digest,

    /// The underlying OCI reference parser rejected the reference.
    #[error("invalid OCI reference: {0}")]
    InvalidReference(#[from] ParseError),

    /// The configured registry client would weaken fail-closed behavior.
    #[error("invalid registry client config: {0}")]
    InvalidClientConfig(&'static str),

    /// The OCI registry client returned an error.
    #[error("registry operation failed: {0}")]
    Registry(#[from] OciDistributionError),

    /// The OCI artifact config media type was not the Chio guard config type.
    #[error("guard OCI config media type mismatch: expected {expected}, got {actual}")]
    ConfigMediaType {
        /// Expected media type.
        expected: &'static str,
        /// Actual media type.
        actual: String,
    },

    /// The OCI artifact layer order or media type was not the normative order.
    #[error("guard OCI layer {index} media type mismatch: expected {expected}, got {actual}")]
    LayerMediaType {
        /// Layer index.
        index: usize,
        /// Expected media type.
        expected: &'static str,
        /// Actual media type.
        actual: String,
    },

    /// The OCI artifact had too few or too many layers.
    #[error("guard OCI artifact must contain exactly 3 layers, got {actual}")]
    LayerCount {
        /// Actual layer count.
        actual: usize,
    },

    /// The publish reference was pinned by digest.
    #[error("guard publish reference must be tag-addressed, not pinned by digest")]
    PublishReferencePinnedByDigest,

    /// The artifact config could not be serialized.
    #[error("failed to serialize guard artifact config: {0}")]
    ConfigSerialize(#[from] serde_json::Error),

    /// No cache root could be derived from XDG_CACHE_HOME or HOME.
    #[error("could not derive Chio guard cache root from XDG_CACHE_HOME or HOME")]
    CacheRootUnavailable,

    /// A cache filesystem operation failed.
    #[error("failed to {operation} guard cache path {path}: {source}")]
    CacheIo {
        /// Filesystem operation being attempted.
        operation: &'static str,
        /// Cache path involved in the operation.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The registry returned a manifest digest that did not match the pinned digest.
    #[error("guard OCI manifest digest mismatch: expected {expected}, got {actual}")]
    ManifestDigestMismatch {
        /// Digest pinned in the pull reference.
        expected: String,
        /// Digest returned by the registry.
        actual: String,
    },

    /// Sigstore verification failed because the artifact signature did not match.
    #[error("guard Sigstore verification failed: artifact signature mismatch")]
    VerifySignatureMismatch,

    /// Sigstore verification failed because the Fulcio subject did not match.
    #[error("guard Sigstore verification failed: Fulcio subject mismatch")]
    VerifyWrongSubject,

    /// Sigstore verification failed because the OIDC issuer did not match.
    #[error("guard Sigstore verification failed: OIDC issuer mismatch")]
    VerifyWrongOidcIssuer,

    /// Sigstore verification failed because Rekor inclusion was missing or invalid.
    #[error("guard Sigstore verification failed: Rekor proof missing or invalid")]
    VerifyMissingRekorProof,

    /// Sigstore verification failed because the certificate is not currently valid.
    #[error("guard Sigstore verification failed: certificate outside validity window")]
    VerifyCertificateExpired,

    /// Sigstore verification failed because the trust root is missing or stale.
    #[error("guard Sigstore verification failed: trust root missing or stale")]
    VerifyTrustRoot,

    /// Sigstore verification failed because the bundle or certificate was malformed.
    #[error("guard Sigstore verification failed: malformed bundle or certificate: {message}")]
    VerifyMalformedBundle {
        /// Verifier-provided parse context.
        message: String,
    },

    /// Sigstore verification failed while reading verification material.
    #[error("guard Sigstore verification I/O failed: {source}")]
    VerifyIo {
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Sigstore verification returned a future error variant. Unknown errors deny.
    #[error("guard Sigstore verification failed closed: {message}")]
    VerifyFailedClosed {
        /// Verifier-provided failure context.
        message: String,
    },
}

/// A validated `sha256:<hex>` digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Return the digest string, including the `sha256:` prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Sha256Digest {
    type Err = GuardRegistryError;

    fn from_str(input: &str) -> Result<Self> {
        let Some(hex) = input.strip_prefix(SHA256_PREFIX) else {
            return Err(GuardRegistryError::InvalidSha256Digest);
        };

        if hex.len() != SHA256_HEX_LEN || !hex.bytes().all(is_lower_hex) {
            return Err(GuardRegistryError::InvalidSha256Digest);
        }

        Ok(Self(input.to_owned()))
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// Digest-pinned Chio guard OCI reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuardOciRef {
    reference: Reference,
    digest: Sha256Digest,
}

impl GuardOciRef {
    /// Return the underlying `oci-distribution` reference.
    pub fn as_oci_reference(&self) -> &Reference {
        &self.reference
    }

    /// Return the explicit registry name.
    pub fn registry(&self) -> &str {
        self.reference.registry()
    }

    /// Return the repository path.
    pub fn repository(&self) -> &str {
        self.reference.repository()
    }

    /// Return the pinned digest.
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

impl fmt::Display for GuardOciRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{OCI_SCHEME}{}", self.reference)
    }
}

impl FromStr for GuardOciRef {
    type Err = GuardRegistryError;

    fn from_str(input: &str) -> Result<Self> {
        let Some(without_scheme) = input.strip_prefix(OCI_SCHEME) else {
            return Err(GuardRegistryError::MissingOciScheme);
        };

        if !has_explicit_registry(without_scheme) {
            return Err(GuardRegistryError::MissingRegistry);
        }

        let digest = match without_scheme.rsplit_once('@') {
            Some((_name, digest)) => Some(digest.parse::<Sha256Digest>()?),
            None => None,
        };
        let has_explicit_tag = has_explicit_tag(without_scheme);
        let reference = without_scheme.parse::<Reference>()?;
        if has_explicit_tag && reference.tag().is_some() {
            return Err(GuardRegistryError::TaggedDigestReference);
        }

        let digest = digest.ok_or(GuardRegistryError::MissingDigest)?;

        Ok(Self { reference, digest })
    }
}

pub(crate) fn has_explicit_registry(reference: &str) -> bool {
    let Some((first_component, _rest)) = reference.split_once('/') else {
        return false;
    };

    first_component == "localhost" || first_component.contains('.') || first_component.contains(':')
}

fn has_explicit_tag(reference: &str) -> bool {
    let last_component = reference.rsplit('/').next().unwrap_or(reference);
    let name = last_component
        .split_once('@')
        .map_or(last_component, |(name, _digest)| name);
    name.contains(':')
}

/// Concrete credentials supported by this scaffold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryCredentials {
    /// Anonymous registry access.
    Anonymous,
    /// HTTP basic registry access.
    Basic {
        /// Registry username.
        username: String,
        /// Registry password or token.
        password: String,
    },
}

impl RegistryCredentials {
    pub(crate) fn to_registry_auth(&self) -> RegistryAuth {
        match self {
            Self::Anonymous => RegistryAuth::Anonymous,
            Self::Basic { username, password } => {
                RegistryAuth::Basic(username.clone(), password.clone())
            }
        }
    }
}

/// Configuration for the guard registry client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardRegistryConfig {
    /// Registries allowed to use HTTP instead of HTTPS.
    pub allow_http_registries: Vec<String>,
    /// Maximum concurrent uploads.
    pub max_concurrent_upload: usize,
    /// Maximum concurrent downloads.
    pub max_concurrent_download: usize,
}

impl Default for GuardRegistryConfig {
    fn default() -> Self {
        Self {
            allow_http_registries: Vec::new(),
            max_concurrent_upload: oci_distribution::client::DEFAULT_MAX_CONCURRENT_UPLOAD,
            max_concurrent_download: oci_distribution::client::DEFAULT_MAX_CONCURRENT_DOWNLOAD,
        }
    }
}

impl GuardRegistryConfig {
    fn validate(&self) -> Result<()> {
        if self.allow_http_registries.iter().any(String::is_empty) {
            return Err(GuardRegistryError::InvalidClientConfig(
                "HTTP registry exceptions must not be empty",
            ));
        }

        if self.max_concurrent_upload == 0 || self.max_concurrent_download == 0 {
            return Err(GuardRegistryError::InvalidClientConfig(
                "registry concurrency limits must be greater than zero",
            ));
        }

        Ok(())
    }

    fn into_oci_config(self) -> Result<ClientConfig> {
        self.validate()?;

        Ok(ClientConfig {
            protocol: if self.allow_http_registries.is_empty() {
                ClientProtocol::Https
            } else {
                ClientProtocol::HttpsExcept(self.allow_http_registries)
            },
            accept_invalid_certificates: false,
            platform_resolver: None,
            max_concurrent_upload: self.max_concurrent_upload,
            max_concurrent_download: self.max_concurrent_download,
            ..ClientConfig::default()
        })
    }
}

/// OCI registry client for guard artifacts.
#[derive(Clone)]
pub struct GuardRegistryClient {
    pub(crate) client: Client,
}

impl GuardRegistryClient {
    /// Build a registry client with fail-closed defaults.
    pub fn try_new(config: GuardRegistryConfig) -> Result<Self> {
        let client = Client::try_from(config.into_oci_config()?)?;
        Ok(Self { client })
    }

    /// Pull a digest-pinned guard artifact and validate its Chio layer shape.
    pub async fn pull_guard_artifact(
        &self,
        reference: &GuardOciRef,
        credentials: &RegistryCredentials,
    ) -> Result<PulledGuardArtifact> {
        let image = self
            .client
            .pull(
                reference.as_oci_reference(),
                &credentials.to_registry_auth(),
                vec![
                    GUARD_WIT_LAYER_MEDIA_TYPE,
                    GUARD_MODULE_LAYER_MEDIA_TYPE,
                    GUARD_MANIFEST_LAYER_MEDIA_TYPE,
                ],
            )
            .await?;

        PulledGuardArtifact::from_image_data(reference.clone(), image)
    }
}

/// A validated pulled guard artifact.
#[derive(Debug, Clone)]
pub struct PulledGuardArtifact {
    /// Digest-pinned source reference.
    pub reference: GuardOciRef,
    /// Raw config blob bytes.
    pub config: Vec<u8>,
    /// WIT layer bytes.
    pub wit: GuardArtifactLayer,
    /// Wasm component layer bytes.
    pub module: GuardArtifactLayer,
    /// Guard manifest layer bytes.
    pub manifest: GuardArtifactLayer,
    /// Registry-reported manifest digest, if supplied by the registry.
    pub registry_manifest_digest: Option<String>,
}

impl PulledGuardArtifact {
    fn from_image_data(reference: GuardOciRef, image: ImageData) -> Result<Self> {
        validate_config(&image.config)?;
        let (wit, module, manifest) = normalize_layers(image.layers)?;

        Ok(Self {
            reference,
            config: image.config.data,
            wit: GuardArtifactLayer::new(wit, GUARD_WIT_LAYER_ROLE),
            module: GuardArtifactLayer::new(module, GUARD_MODULE_LAYER_ROLE),
            manifest: GuardArtifactLayer::new(manifest, GUARD_MANIFEST_LAYER_ROLE),
            registry_manifest_digest: image.digest,
        })
    }
}

fn validate_config(config: &Config) -> Result<()> {
    if config.media_type != GUARD_CONFIG_MEDIA_TYPE {
        return Err(GuardRegistryError::ConfigMediaType {
            expected: GUARD_CONFIG_MEDIA_TYPE,
            actual: config.media_type.clone(),
        });
    }

    Ok(())
}

fn normalize_layers(layers: Vec<ImageLayer>) -> Result<(ImageLayer, ImageLayer, ImageLayer)> {
    const EXPECTED_LEN: usize = 3;

    if layers.len() != EXPECTED_LEN {
        return Err(GuardRegistryError::LayerCount {
            actual: layers.len(),
        });
    }

    let mut layers = layers;
    let wit = take_layer(&mut layers, 0, GUARD_WIT_LAYER_MEDIA_TYPE)?;
    let module = take_layer(&mut layers, 1, GUARD_MODULE_LAYER_MEDIA_TYPE)?;
    let manifest = take_layer(&mut layers, 2, GUARD_MANIFEST_LAYER_MEDIA_TYPE)?;

    Ok((wit, module, manifest))
}

fn take_layer(
    layers: &mut Vec<ImageLayer>,
    index: usize,
    expected: &'static str,
) -> Result<ImageLayer> {
    let Some(position) = layers.iter().position(|layer| layer.media_type == expected) else {
        let actual = layers
            .get(index)
            .or_else(|| layers.first())
            .map_or_else(|| "<missing>".to_owned(), |layer| layer.media_type.clone());
        return Err(GuardRegistryError::LayerMediaType {
            index,
            expected,
            actual,
        });
    };

    Ok(layers.remove(position))
}

/// Layer bytes with their normalized Chio role.
#[derive(Debug, Clone)]
pub struct GuardArtifactLayer {
    /// Raw layer bytes.
    pub data: Vec<u8>,
    /// OCI layer media type.
    pub media_type: String,
    /// Chio role from the normative layer order.
    pub role: &'static str,
}

impl GuardArtifactLayer {
    fn new(layer: ImageLayer, role: &'static str) -> Self {
        Self {
            data: layer.data,
            media_type: layer.media_type,
            role,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn parses_digest_pinned_oci_reference() {
        let parsed = match format!("oci://ghcr.io/chio/tool-gate@{DIGEST}").parse::<GuardOciRef>() {
            Ok(parsed) => parsed,
            Err(error) => panic!("reference should parse: {error}"),
        };

        assert_eq!(parsed.registry(), "ghcr.io");
        assert_eq!(parsed.repository(), "chio/tool-gate");
        assert_eq!(parsed.digest().as_str(), DIGEST);
        assert_eq!(
            parsed.to_string(),
            "oci://ghcr.io/chio/tool-gate@sha256:1111111111111111111111111111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn rejects_ambiguous_or_unpinned_references() {
        assert!(matches!(
            "ghcr.io/chio/tool-gate@sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .parse::<GuardOciRef>(),
            Err(GuardRegistryError::MissingOciScheme)
        ));
        assert!(matches!(
            "oci://tool-gate@sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .parse::<GuardOciRef>(),
            Err(GuardRegistryError::MissingRegistry)
        ));
        assert!(matches!(
            "oci://ghcr.io/chio/tool-gate:latest".parse::<GuardOciRef>(),
            Err(GuardRegistryError::TaggedDigestReference)
        ));
        assert!(matches!(
            "oci://ghcr.io/chio/tool-gate:latest@sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .parse::<GuardOciRef>(),
            Err(GuardRegistryError::TaggedDigestReference)
        ));
        assert!(matches!(
            "oci://ghcr.io/chio/tool-gate@sha256:AAAA111111111111111111111111111111111111111111111111111111111111"
                .parse::<GuardOciRef>(),
            Err(GuardRegistryError::InvalidSha256Digest)
        ));
    }

    #[test]
    fn registry_config_defaults_are_fail_closed() {
        let config = match GuardRegistryConfig::default().into_oci_config() {
            Ok(config) => config,
            Err(error) => panic!("default config should validate: {error}"),
        };

        assert!(matches!(config.protocol, ClientProtocol::Https));
        assert!(!config.accept_invalid_certificates);
        assert!(config.platform_resolver.is_none());
        assert!(config.max_concurrent_upload > 0);
        assert!(config.max_concurrent_download > 0);
    }

    #[test]
    fn rejects_invalid_registry_config() {
        let empty_http_exception = GuardRegistryConfig {
            allow_http_registries: vec![String::new()],
            ..GuardRegistryConfig::default()
        };
        assert!(matches!(
            empty_http_exception.into_oci_config(),
            Err(GuardRegistryError::InvalidClientConfig(_))
        ));

        let zero_concurrency = GuardRegistryConfig {
            max_concurrent_upload: 0,
            ..GuardRegistryConfig::default()
        };
        assert!(matches!(
            zero_concurrency.into_oci_config(),
            Err(GuardRegistryError::InvalidClientConfig(_))
        ));
    }

    #[test]
    fn validates_guard_artifact_shape() {
        let reference = parsed_reference();
        let image = image_data(vec![
            ImageLayer::new(vec![3], GUARD_MANIFEST_LAYER_MEDIA_TYPE.to_owned(), None),
            ImageLayer::new(vec![1], GUARD_WIT_LAYER_MEDIA_TYPE.to_owned(), None),
            ImageLayer::new(vec![2], GUARD_MODULE_LAYER_MEDIA_TYPE.to_owned(), None),
        ]);

        let artifact = match PulledGuardArtifact::from_image_data(reference, image) {
            Ok(artifact) => artifact,
            Err(error) => panic!("artifact should validate: {error}"),
        };

        assert_eq!(artifact.config, b"{}".to_vec());
        assert_eq!(artifact.wit.role, GUARD_WIT_LAYER_ROLE);
        assert_eq!(artifact.wit.data, vec![1]);
        assert_eq!(artifact.module.role, GUARD_MODULE_LAYER_ROLE);
        assert_eq!(artifact.module.data, vec![2]);
        assert_eq!(artifact.manifest.role, GUARD_MANIFEST_LAYER_ROLE);
        assert_eq!(artifact.manifest.data, vec![3]);
        assert_eq!(artifact.registry_manifest_digest.as_deref(), Some(DIGEST));
    }

    #[test]
    fn rejects_wrong_guard_artifact_shape() {
        let reference = parsed_reference();
        let wrong_config = ImageData {
            config: Config::new(b"{}".to_vec(), "application/json".to_owned(), None),
            ..image_data(vec![
                ImageLayer::new(vec![1], GUARD_WIT_LAYER_MEDIA_TYPE.to_owned(), None),
                ImageLayer::new(vec![2], GUARD_MODULE_LAYER_MEDIA_TYPE.to_owned(), None),
                ImageLayer::new(vec![3], GUARD_MANIFEST_LAYER_MEDIA_TYPE.to_owned(), None),
            ])
        };
        assert!(matches!(
            PulledGuardArtifact::from_image_data(reference.clone(), wrong_config),
            Err(GuardRegistryError::ConfigMediaType { .. })
        ));

        let missing_layer = image_data(vec![
            ImageLayer::new(vec![1], GUARD_WIT_LAYER_MEDIA_TYPE.to_owned(), None),
            ImageLayer::new(vec![2], GUARD_MODULE_LAYER_MEDIA_TYPE.to_owned(), None),
        ]);
        assert!(matches!(
            PulledGuardArtifact::from_image_data(reference.clone(), missing_layer),
            Err(GuardRegistryError::LayerCount { actual: 2 })
        ));

        let duplicate_layer = image_data(vec![
            ImageLayer::new(vec![1], GUARD_WIT_LAYER_MEDIA_TYPE.to_owned(), None),
            ImageLayer::new(vec![2], GUARD_MODULE_LAYER_MEDIA_TYPE.to_owned(), None),
            ImageLayer::new(vec![3], GUARD_MODULE_LAYER_MEDIA_TYPE.to_owned(), None),
        ]);
        assert!(matches!(
            PulledGuardArtifact::from_image_data(reference, duplicate_layer),
            Err(GuardRegistryError::LayerMediaType { index: 2, .. })
        ));
    }

    fn parsed_reference() -> GuardOciRef {
        match format!("oci://ghcr.io/chio/tool-gate@{DIGEST}").parse::<GuardOciRef>() {
            Ok(reference) => reference,
            Err(error) => panic!("test reference should parse: {error}"),
        }
    }

    fn image_data(layers: Vec<ImageLayer>) -> ImageData {
        ImageData {
            layers,
            digest: Some(DIGEST.to_owned()),
            config: Config::new(b"{}".to_vec(), GUARD_CONFIG_MEDIA_TYPE.to_owned(), None),
            manifest: None,
        }
    }
}
