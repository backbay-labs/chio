//! OCI distribution primitives for Chio guard artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use chio_egress_contract::{
    client_builder_with_contract, send_with_contract, ContractResponse, HttpEgressContract,
};
use oci_distribution::client::{ClientConfig, ClientProtocol, Config, ImageData, ImageLayer};
use oci_distribution::errors::OciDistributionError;
use oci_distribution::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE;
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::{Client, ParseError, Reference};
use reqwest::header::{ACCEPT, USER_AGENT, WWW_AUTHENTICATE};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// OCI artifact media type for a Chio guard bundle.
pub const GUARD_ARTIFACT_MEDIA_TYPE: &str = "application/vnd.chio.guard.v1+wasm";
/// OCI config media type for guard runtime metadata.
pub const GUARD_CONFIG_MEDIA_TYPE: &str = "application/vnd.chio.guard.config.v1+json";
/// WIT contract layer media type.
pub const GUARD_WIT_LAYER_MEDIA_TYPE: &str = "application/vnd.chio.guard.wit.v1";
/// Wasm component layer media type.
pub const GUARD_MODULE_LAYER_MEDIA_TYPE: &str = "application/vnd.chio.guard.module.v1+wasm";
/// Chio guard manifest layer media type.
pub const GUARD_MANIFEST_LAYER_MEDIA_TYPE: &str = "application/vnd.chio.guard.manifest.v1+json";
/// Sigstore bundle media type used by OCI 1.1 referrer attachments.
pub const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
/// OCI artifact manifest media type.
pub const OCI_ARTIFACT_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.artifact.manifest.v1+json";
/// Annotation role for the WIT layer.
pub const GUARD_WIT_LAYER_ROLE: &str = "wit";
/// Annotation role for the wasm layer.
pub const GUARD_MODULE_LAYER_ROLE: &str = "wasm";
/// Annotation role for the manifest layer.
pub const GUARD_MANIFEST_LAYER_ROLE: &str = "manifest";

pub(crate) const OCI_SCHEME: &str = "oci://";
const SHA256_PREFIX: &str = "sha256:";
const SHA256_HEX_LEN: usize = 64;
const REGISTRY_HTTP_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const REGISTRY_HTTP_MAX_REDIRECT_CHAIN: u8 = 3;

/// Result type for guard registry operations.
pub type Result<T> = std::result::Result<T, GuardRegistryError>;

/// Errors returned by the guard registry.
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

    /// The publish reference did not carry an explicit tag.
    #[error("guard publish reference must include an explicit tag")]
    PublishReferenceMissingTag,

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

    /// The OCI image manifest digest did not match the pinned digest.
    #[error("guard OCI manifest digest mismatch: expected {expected}, got {actual}")]
    ManifestDigestMismatch {
        /// Digest pinned in the pull reference.
        expected: String,
        /// Digest returned by the registry.
        actual: String,
    },

    /// Pulled blob bytes did not match their pinned OCI manifest descriptor.
    #[error(
        "guard OCI descriptor digest mismatch for {artifact}: expected {expected}, got {actual}"
    )]
    DescriptorDigestMismatch {
        /// Artifact component being checked.
        artifact: &'static str,
        /// Digest recorded in the OCI manifest descriptor.
        expected: String,
        /// Digest computed from the pulled blob bytes.
        actual: String,
    },

    /// A pinned OCI manifest descriptor used the wrong media type.
    #[error("guard OCI descriptor media type mismatch for {artifact}: expected {expected}, got {actual}")]
    DescriptorMediaTypeMismatch {
        /// Artifact component being checked.
        artifact: &'static str,
        /// Expected media type.
        expected: &'static str,
        /// Actual media type.
        actual: String,
    },

    /// Pulled blob bytes had a different size from their OCI descriptor.
    #[error(
        "guard OCI descriptor size mismatch for {artifact}: expected {expected}, got {actual}"
    )]
    DescriptorSizeMismatch {
        /// Artifact component being checked.
        artifact: &'static str,
        /// Size recorded in the OCI manifest descriptor.
        expected: i64,
        /// Size computed from the pulled blob bytes.
        actual: i64,
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

    /// The registry referrers API request failed.
    #[error("guard OCI referrers request failed for {url}: {source}")]
    ReferrersRequest {
        /// Referrers or blob URL.
        url: String,
        /// Underlying HTTP error.
        #[source]
        source: reqwest::Error,
    },

    /// The registry referrers API request was denied by the typed egress contract.
    #[error("guard OCI referrers request denied by HttpEgressContract for {url}: {source}")]
    ReferrersEgress {
        /// Referrers, blob, or token URL.
        url: String,
        /// Typed egress contract denial.
        #[source]
        source: chio_egress_contract::HttpEgressError,
    },

    /// The registry referrers API returned an error status.
    #[error("guard OCI referrers request failed for {url}: HTTP {status}: {body}")]
    ReferrersStatus {
        /// Referrers or blob URL.
        url: String,
        /// HTTP status code.
        status: reqwest::StatusCode,
        /// Response body, truncated by the caller.
        body: String,
    },

    /// The registry returned malformed referrers or bundle manifest JSON.
    #[error("guard OCI referrers response was malformed: {message}")]
    ReferrersMalformed {
        /// Parse or shape failure context.
        message: String,
    },

    /// A Sigstore verification policy was requested but no bundle was found.
    #[error("guard Sigstore verification requested but no Sigstore bundle was found in OCI referrers or local input")]
    SigstoreBundleNotFound,
}

/// A validated `sha256:<hex>` digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
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
    pub fn as_oci_reference(&self) -> &Reference {
        &self.reference
    }

    pub fn registry(&self) -> &str {
        self.reference.registry()
    }

    pub fn repository(&self) -> &str {
        self.reference.repository()
    }

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

pub(crate) fn has_explicit_tag(reference: &str) -> bool {
    let last_component = reference.rsplit('/').next().unwrap_or(reference);
    let name = last_component
        .split_once('@')
        .map_or(last_component, |(name, _digest)| name);
    name.contains(':')
}

/// Registry credentials supported by the OCI client.
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
    allow_http_registries: Vec<String>,
}

impl GuardRegistryClient {
    /// Build a registry client with fail-closed defaults.
    pub fn try_new(config: GuardRegistryConfig) -> Result<Self> {
        let allow_http_registries = config.allow_http_registries.clone();
        let client = Client::try_from(config.into_oci_config()?)?;
        Ok(Self {
            client,
            allow_http_registries,
        })
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

    /// Discover and pull a Sigstore bundle attached with OCI 1.1 referrers.
    pub async fn pull_sigstore_bundle_referrer(
        &self,
        reference: &GuardOciRef,
        credentials: &RegistryCredentials,
    ) -> Result<Option<Vec<u8>>> {
        let Some(referrer) = self
            .sigstore_referrer_descriptor(reference, credentials)
            .await?
        else {
            return Ok(None);
        };

        let manifest_reference = Reference::with_digest(
            reference.registry().to_string(),
            reference.repository().to_string(),
            referrer.digest.clone(),
        );
        let (manifest_json, manifest_digest) = self
            .client
            .pull_manifest_raw(
                &manifest_reference,
                &credentials.to_registry_auth(),
                &[
                    OCI_ARTIFACT_MANIFEST_MEDIA_TYPE,
                    oci_distribution::manifest::OCI_IMAGE_MEDIA_TYPE,
                ],
            )
            .await?;
        if manifest_digest != referrer.digest {
            return Err(GuardRegistryError::ManifestDigestMismatch {
                expected: referrer.digest,
                actual: manifest_digest,
            });
        }
        let bundle_descriptor =
            sigstore_bundle_descriptor_from_manifest(&manifest_json, reference.digest().as_str())?;
        self.pull_registry_blob(reference, credentials, &bundle_descriptor)
            .await
            .map(Some)
    }

    async fn sigstore_referrer_descriptor(
        &self,
        reference: &GuardOciRef,
        credentials: &RegistryCredentials,
    ) -> Result<Option<ReferrerDescriptor>> {
        let url = format!(
            "{}://{}/v2/{}/referrers/{}",
            self.scheme_for(reference.registry()),
            reference.registry(),
            reference.repository(),
            reference.digest()
        );
        let Some(body) = self
            .registry_get(
                reference,
                credentials,
                &url,
                &[("artifactType", SIGSTORE_BUNDLE_MEDIA_TYPE)],
                OCI_IMAGE_INDEX_MEDIA_TYPE,
                RegistryNotFoundBehavior::Error,
            )
            .await?
        else {
            return Ok(None);
        };
        let index: ReferrersIndex = serde_json::from_slice(&body).map_err(|source| {
            GuardRegistryError::ReferrersMalformed {
                message: format!("parse referrers index: {source}"),
            }
        })?;
        let mut candidates = index
            .manifests
            .into_iter()
            .filter(|descriptor| {
                descriptor
                    .artifact_type
                    .as_deref()
                    .is_some_and(|artifact_type| artifact_type == SIGSTORE_BUNDLE_MEDIA_TYPE)
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.digest.cmp(&right.digest));
        Ok(candidates.into_iter().next())
    }

    async fn pull_registry_blob(
        &self,
        reference: &GuardOciRef,
        credentials: &RegistryCredentials,
        descriptor: &ReferrerBlobDescriptor,
    ) -> Result<Vec<u8>> {
        if descriptor.media_type != SIGSTORE_BUNDLE_MEDIA_TYPE {
            return Err(GuardRegistryError::DescriptorMediaTypeMismatch {
                artifact: "sigstore_bundle",
                expected: SIGSTORE_BUNDLE_MEDIA_TYPE,
                actual: descriptor.media_type.clone(),
            });
        }
        let url = format!(
            "{}://{}/v2/{}/blobs/{}",
            self.scheme_for(reference.registry()),
            reference.registry(),
            reference.repository(),
            descriptor.digest
        );
        let Some(body) = self
            .registry_get(
                reference,
                credentials,
                &url,
                &[],
                SIGSTORE_BUNDLE_MEDIA_TYPE,
                RegistryNotFoundBehavior::ReturnNone,
            )
            .await?
        else {
            return Err(GuardRegistryError::ReferrersStatus {
                url,
                status: reqwest::StatusCode::NOT_FOUND,
                body: "Sigstore bundle blob was not found".to_string(),
            });
        };
        let actual_size = i64::try_from(body.len()).unwrap_or(i64::MAX);
        if actual_size != descriptor.size {
            return Err(GuardRegistryError::DescriptorSizeMismatch {
                artifact: "sigstore_bundle",
                expected: descriptor.size,
                actual: actual_size,
            });
        }
        let actual_digest = format!("sha256:{:x}", Sha256::digest(&body));
        if actual_digest != descriptor.digest {
            return Err(GuardRegistryError::DescriptorDigestMismatch {
                artifact: "sigstore_bundle",
                expected: descriptor.digest.clone(),
                actual: actual_digest,
            });
        }
        Ok(body)
    }

    async fn registry_get(
        &self,
        reference: &GuardOciRef,
        credentials: &RegistryCredentials,
        url: &str,
        query: &[(&str, &str)],
        accept: &str,
        not_found_behavior: RegistryNotFoundBehavior,
    ) -> Result<Option<Vec<u8>>> {
        let contract = self.registry_egress_contract_for_url(url)?;
        let client = self.registry_http_client(url, &contract)?;
        let mut request = client
            .get(url)
            .header(USER_AGENT, "chio-guard-registry")
            .header(ACCEPT, accept)
            .query(query);
        if let RegistryCredentials::Basic { username, password } = credentials {
            request = request.basic_auth(username, Some(password));
        }
        let response = self
            .send_registry_request(url, &contract, &client, request)
            .await?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_bearer_challenge);
            if let Some(challenge) = challenge {
                let token = self
                    .registry_bearer_token(reference, credentials, &challenge)
                    .await?;
                let response = client
                    .get(url)
                    .header(USER_AGENT, "chio-guard-registry")
                    .header(ACCEPT, accept)
                    .bearer_auth(token)
                    .query(query);
                let response = self
                    .send_registry_request(url, &contract, &client, response)
                    .await?;
                return registry_response_body(url, response, not_found_behavior);
            }
        }

        registry_response_body(url, response, not_found_behavior)
    }

    async fn registry_bearer_token(
        &self,
        reference: &GuardOciRef,
        credentials: &RegistryCredentials,
        challenge: &BearerChallenge,
    ) -> Result<String> {
        let scope = format!("repository:{}:pull", reference.repository());
        let contract = self.registry_egress_contract_for_url(&challenge.realm)?;
        let client = self.registry_http_client(&challenge.realm, &contract)?;
        let mut request = client
            .get(&challenge.realm)
            .header(USER_AGENT, "chio-guard-registry")
            .query(&[("scope", scope.as_str())]);
        if let Some(service) = challenge.service.as_deref() {
            request = request.query(&[("service", service)]);
        }
        if let RegistryCredentials::Basic { username, password } = credentials {
            request = request.basic_auth(username, Some(password));
        }
        let response = self
            .send_registry_request(&challenge.realm, &contract, &client, request)
            .await?;
        let body = registry_response_body(
            &challenge.realm,
            response,
            RegistryNotFoundBehavior::ReturnNone,
        )?
        .ok_or_else(|| GuardRegistryError::ReferrersMalformed {
            message: "token response unexpectedly returned 404".to_string(),
        })?;
        let token: RegistryTokenResponse = serde_json::from_slice(&body).map_err(|source| {
            GuardRegistryError::ReferrersMalformed {
                message: format!("parse registry token response: {source}"),
            }
        })?;
        token
            .token
            .or(token.access_token)
            .ok_or_else(|| GuardRegistryError::ReferrersMalformed {
                message: "registry token response omitted token".to_string(),
            })
    }

    fn scheme_for(&self, registry: &str) -> &'static str {
        if self
            .allow_http_registries
            .iter()
            .any(|allowed| allowed == registry)
        {
            "http"
        } else {
            "https"
        }
    }

    fn registry_egress_contract_for_url(&self, url: &str) -> Result<HttpEgressContract> {
        let parsed =
            reqwest::Url::parse(url).map_err(|source| GuardRegistryError::ReferrersMalformed {
                message: format!("invalid registry URL `{url}`: {source}"),
            })?;
        let scheme = parsed.scheme().to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https") {
            return Err(GuardRegistryError::ReferrersMalformed {
                message: format!("registry URL `{url}` used unsupported scheme `{scheme}`"),
            });
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| GuardRegistryError::ReferrersMalformed {
                message: format!("registry URL `{url}` omitted a host"),
            })?;
        let authority = normalized_reqwest_url_authority(&parsed)?;
        let http_allowlisted = self
            .allow_http_registries
            .iter()
            .any(|allowed| allowed == host || allowed == &authority);
        if scheme == "http" && !http_allowlisted {
            return Err(GuardRegistryError::InvalidClientConfig(
                "HTTP guard registry referrer requests require allow_http_registries",
            ));
        }
        let mut allowed_schemes = BTreeSet::new();
        allowed_schemes.insert(scheme);
        let mut allowed_authority_set = BTreeSet::new();
        allowed_authority_set.insert(authority);
        Ok(HttpEgressContract {
            tenant_egress_namespace: "chio-guard-registry".to_string(),
            allowed_schemes,
            allowed_authority_set,
            deny_loopback: !http_allowlisted,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: REGISTRY_HTTP_MAX_REDIRECT_CHAIN,
            max_response_bytes: REGISTRY_HTTP_MAX_RESPONSE_BYTES,
        })
    }

    fn registry_http_client(
        &self,
        url: &str,
        contract: &HttpEgressContract,
    ) -> Result<reqwest::Client> {
        client_builder_with_contract(contract)
            .build()
            .map_err(|source| GuardRegistryError::ReferrersRequest {
                url: url.to_string(),
                source,
            })
    }

    async fn send_registry_request(
        &self,
        url: &str,
        contract: &HttpEgressContract,
        client: &reqwest::Client,
        request: reqwest::RequestBuilder,
    ) -> Result<ContractResponse> {
        let request = request
            .build()
            .map_err(|source| GuardRegistryError::ReferrersRequest {
                url: url.to_string(),
                source,
            })?;
        send_with_contract(contract, client, request)
            .await
            .map_err(|source| GuardRegistryError::ReferrersEgress {
                url: url.to_string(),
                source,
            })
    }
}

#[derive(Clone, Copy)]
enum RegistryNotFoundBehavior {
    ReturnNone,
    Error,
}

fn registry_response_body(
    url: &str,
    response: ContractResponse,
    not_found_behavior: RegistryNotFoundBehavior,
) -> Result<Option<Vec<u8>>> {
    let status = response.status();
    let body = response.body();
    if status == reqwest::StatusCode::NOT_FOUND {
        return match not_found_behavior {
            RegistryNotFoundBehavior::ReturnNone => Ok(None),
            RegistryNotFoundBehavior::Error => Err(GuardRegistryError::ReferrersStatus {
                url: url.to_string(),
                status,
                body: String::from_utf8_lossy(body).chars().take(512).collect(),
            }),
        };
    }
    if !status.is_success() {
        return Err(GuardRegistryError::ReferrersStatus {
            url: url.to_string(),
            status,
            body: String::from_utf8_lossy(body).chars().take(512).collect(),
        });
    }
    Ok(Some(body.to_vec()))
}

fn normalized_reqwest_url_authority(url: &reqwest::Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| GuardRegistryError::ReferrersMalformed {
            message: format!("registry URL `{url}` omitted a host"),
        })?;
    let host = host.to_ascii_lowercase();
    let host_authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };
    Ok(match url.port() {
        Some(port) => format!("{host_authority}:{port}"),
        None => host_authority,
    })
}

fn parse_bearer_challenge(input: &str) -> Option<BearerChallenge> {
    let fields = input.strip_prefix("Bearer ")?;
    let mut values = BTreeMap::new();
    for field in fields.split(',') {
        let (key, value) = field.trim().split_once('=')?;
        values.insert(
            key.trim().to_string(),
            value.trim().trim_matches('"').to_string(),
        );
    }
    let realm = values.remove("realm")?;
    Some(BearerChallenge {
        realm,
        service: values.remove("service"),
    })
}

fn sigstore_bundle_descriptor_from_manifest(
    manifest_json: &[u8],
    expected_subject_digest: &str,
) -> Result<ReferrerBlobDescriptor> {
    let manifest: SigstoreArtifactManifest =
        serde_json::from_slice(manifest_json).map_err(|source| {
            GuardRegistryError::ReferrersMalformed {
                message: format!("parse Sigstore artifact manifest: {source}"),
            }
        })?;
    if manifest.artifact_type.as_deref() != Some(SIGSTORE_BUNDLE_MEDIA_TYPE) {
        return Err(GuardRegistryError::ReferrersMalformed {
            message: "Sigstore artifact manifest did not carry the Sigstore bundle artifactType"
                .to_string(),
        });
    }
    let subject = manifest
        .subject
        .ok_or_else(|| GuardRegistryError::ReferrersMalformed {
            message: "Sigstore artifact manifest did not declare a subject".to_string(),
        })?;
    if subject.digest != expected_subject_digest {
        return Err(GuardRegistryError::ManifestDigestMismatch {
            expected: expected_subject_digest.to_owned(),
            actual: subject.digest,
        });
    }
    let blobs = manifest.blobs.or(manifest.layers).unwrap_or_default();
    blobs
        .into_iter()
        .find(|descriptor| descriptor.media_type == SIGSTORE_BUNDLE_MEDIA_TYPE)
        .ok_or_else(|| GuardRegistryError::ReferrersMalformed {
            message: "Sigstore artifact manifest did not contain a Sigstore bundle blob"
                .to_string(),
        })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferrersIndex {
    manifests: Vec<ReferrerDescriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferrerDescriptor {
    digest: String,
    #[serde(default)]
    artifact_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigstoreArtifactManifest {
    #[serde(default)]
    artifact_type: Option<String>,
    #[serde(default)]
    subject: Option<ReferrerBlobDescriptor>,
    #[serde(default)]
    blobs: Option<Vec<ReferrerBlobDescriptor>>,
    #[serde(default)]
    layers: Option<Vec<ReferrerBlobDescriptor>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferrerBlobDescriptor {
    media_type: String,
    digest: String,
    size: i64,
}

struct BearerChallenge {
    realm: String,
    service: Option<String>,
}

#[derive(Deserialize)]
struct RegistryTokenResponse {
    token: Option<String>,
    access_token: Option<String>,
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
    use crate::publish::GUARD_OCI_MANIFEST_MEDIA_TYPE;

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
    fn parses_registry_bearer_challenge() {
        let challenge =
            parse_bearer_challenge(r#"Bearer realm="https://ghcr.io/token",service="ghcr.io""#)
                .unwrap_or_else(|| panic!("bearer challenge should parse"));

        assert_eq!(challenge.realm, "https://ghcr.io/token");
        assert_eq!(challenge.service.as_deref(), Some("ghcr.io"));
    }

    #[test]
    fn extracts_sigstore_bundle_descriptor_from_artifact_manifest() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_ARTIFACT_MANIFEST_MEDIA_TYPE,
            "artifactType": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "subject": {
                "mediaType": GUARD_OCI_MANIFEST_MEDIA_TYPE,
                "digest": DIGEST,
                "size": 4096
            },
            "blobs": [{
                "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
                "digest": DIGEST,
                "size": 17
            }]
        });
        let descriptor = sigstore_bundle_descriptor_from_manifest(
            serde_json::to_vec(&manifest)
                .unwrap_or_else(|error| panic!("manifest should serialize: {error}"))
                .as_slice(),
            DIGEST,
        )
        .unwrap_or_else(|error| panic!("descriptor should parse: {error}"));

        assert_eq!(descriptor.media_type, SIGSTORE_BUNDLE_MEDIA_TYPE);
        assert_eq!(descriptor.digest, DIGEST);
        assert_eq!(descriptor.size, 17);
    }

    #[test]
    fn rejects_sigstore_artifact_manifest_without_subject() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_ARTIFACT_MANIFEST_MEDIA_TYPE,
            "artifactType": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "blobs": [{
                "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
                "digest": DIGEST,
                "size": 17
            }]
        });
        let err = match sigstore_bundle_descriptor_from_manifest(
            serde_json::to_vec(&manifest)
                .unwrap_or_else(|error| panic!("manifest should serialize: {error}"))
                .as_slice(),
            DIGEST,
        ) {
            Ok(descriptor) => panic!(
                "Sigstore artifact manifest without subject must be rejected, got {descriptor:?}"
            ),
            Err(error) => error,
        };

        assert!(
            matches!(err, GuardRegistryError::ReferrersMalformed { ref message } if message.contains("subject")),
            "expected missing subject error, got {err:?}"
        );
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
