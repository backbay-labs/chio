//! Publish support for Chio guard OCI artifacts.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use oci_distribution::client::{Config, ImageLayer, PushResponse};
use oci_distribution::manifest::{OciImageManifest, OCI_IMAGE_MEDIA_TYPE};
use oci_distribution::Reference;
use serde::{Deserialize, Serialize};

use crate::oci::{
    has_explicit_registry, GuardRegistryClient, GuardRegistryError, RegistryCredentials, Result,
    GUARD_ARTIFACT_MEDIA_TYPE, GUARD_CONFIG_MEDIA_TYPE, GUARD_MANIFEST_LAYER_MEDIA_TYPE,
    GUARD_MANIFEST_LAYER_ROLE, GUARD_MODULE_LAYER_MEDIA_TYPE, GUARD_MODULE_LAYER_ROLE,
    GUARD_WIT_LAYER_MEDIA_TYPE, GUARD_WIT_LAYER_ROLE, OCI_SCHEME,
};

/// Current Chio guard WIT world pinned by the v2 artifact schema.
pub const GUARD_WIT_WORLD: &str = "chio:guard/guard@0.2.0";
/// Annotation key for the semantic role of each guard layer.
pub const GUARD_LAYER_ROLE_ANNOTATION: &str = "org.chio.layer.role";
/// Manifest annotation key for the WIT world.
pub const GUARD_WIT_WORLD_ANNOTATION: &str = "org.chio.guard.wit_world";
/// Manifest annotation key for the Sigstore signer subject.
pub const GUARD_SIGNER_SUBJECT_ANNOTATION: &str = "org.chio.guard.signer_subject";
/// OCI image manifest media type required by the Chio guard artifact schema.
pub const GUARD_OCI_MANIFEST_MEDIA_TYPE: &str = OCI_IMAGE_MEDIA_TYPE;

/// Tag-addressed OCI reference used when publishing a guard artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuardPublishRef {
    reference: Reference,
}

impl GuardPublishRef {
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

    /// Return the publish tag.
    pub fn tag(&self) -> &str {
        self.reference.tag().unwrap_or("latest")
    }
}

impl fmt::Display for GuardPublishRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{OCI_SCHEME}{}", self.reference)
    }
}

impl FromStr for GuardPublishRef {
    type Err = GuardRegistryError;

    fn from_str(input: &str) -> Result<Self> {
        let Some(without_scheme) = input.strip_prefix(OCI_SCHEME) else {
            return Err(GuardRegistryError::MissingOciScheme);
        };

        if !has_explicit_registry(without_scheme) {
            return Err(GuardRegistryError::MissingRegistry);
        }

        let reference = without_scheme.parse::<Reference>()?;
        if reference.digest().is_some() {
            return Err(GuardRegistryError::PublishReferencePinnedByDigest);
        }

        Ok(Self { reference })
    }
}

/// JSON config blob stored in the OCI artifact config descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardArtifactConfig {
    /// Schema version discriminator.
    pub schema_version: String,
    /// WIT world compiled by the guard component.
    pub wit_world: String,
    /// Ed25519 signer public key encoded as `ed25519:<base64>`.
    pub signer_public_key: String,
    /// Runtime fuel limit.
    pub fuel_limit: u64,
    /// Runtime memory limit in bytes.
    pub memory_limit_bytes: u64,
    /// Operator-provided epoch seed.
    pub epoch_id_seed: String,
}

impl GuardArtifactConfig {
    /// Build a v2 config blob for the current guard WIT world.
    pub fn new(
        signer_public_key: impl Into<String>,
        fuel_limit: u64,
        memory_limit_bytes: u64,
        epoch_id_seed: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: "chio.guard.config.v2".to_owned(),
            wit_world: GUARD_WIT_WORLD.to_owned(),
            signer_public_key: signer_public_key.into(),
            fuel_limit,
            memory_limit_bytes,
            epoch_id_seed: epoch_id_seed.into(),
        }
    }
}

/// Inputs used to construct the three-layer publish artifact.
#[derive(Debug, Clone)]
pub struct GuardPublishArtifactInput {
    /// Raw WIT bytes for `chio:guard/guard@0.2.0`.
    pub wit: Vec<u8>,
    /// Raw wasm component bytes.
    pub module: Vec<u8>,
    /// Raw guard manifest bytes.
    pub manifest: Vec<u8>,
    /// Config blob fields.
    pub config: GuardArtifactConfig,
    /// Optional Sigstore signer subject annotation.
    pub signer_subject: Option<String>,
}

/// Built artifact data ready for an OCI registry push.
#[derive(Clone)]
pub struct GuardPublishArtifact {
    /// Config blob with the Chio guard config media type.
    pub config: Config,
    /// Layers in normative Chio order: WIT, wasm module, guard manifest.
    pub layers: Vec<ImageLayer>,
    /// OCI image manifest with Chio artifact type and descriptors.
    pub manifest: OciImageManifest,
}

impl GuardPublishArtifact {
    /// Build the publish artifact without performing any network I/O.
    pub fn build(input: GuardPublishArtifactInput) -> Result<Self> {
        let config_bytes = serde_json::to_vec(&input.config)?;
        let config = Config::new(config_bytes, GUARD_CONFIG_MEDIA_TYPE.to_owned(), None);

        let layers = vec![
            layer(input.wit, GUARD_WIT_LAYER_MEDIA_TYPE, GUARD_WIT_LAYER_ROLE),
            layer(
                input.module,
                GUARD_MODULE_LAYER_MEDIA_TYPE,
                GUARD_MODULE_LAYER_ROLE,
            ),
            layer(
                input.manifest,
                GUARD_MANIFEST_LAYER_MEDIA_TYPE,
                GUARD_MANIFEST_LAYER_ROLE,
            ),
        ];

        let mut annotations = HashMap::from([(
            GUARD_WIT_WORLD_ANNOTATION.to_owned(),
            input.config.wit_world.clone(),
        )]);
        if let Some(signer_subject) = input.signer_subject {
            annotations.insert(GUARD_SIGNER_SUBJECT_ANNOTATION.to_owned(), signer_subject);
        }

        let mut manifest = OciImageManifest::build(&layers, &config, Some(annotations));
        manifest.media_type = Some(GUARD_OCI_MANIFEST_MEDIA_TYPE.to_owned());
        manifest.artifact_type = Some(GUARD_ARTIFACT_MEDIA_TYPE.to_owned());

        Ok(Self {
            config,
            layers,
            manifest,
        })
    }
}

/// Registry push result for a guard publish operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardPublishResponse {
    /// Pullable URL for the config blob.
    pub config_url: String,
    /// Pullable URL for the image manifest.
    pub manifest_url: String,
    /// Digest of the config blob included in the manifest descriptor.
    pub config_digest: String,
}

impl GuardRegistryClient {
    /// Push a prebuilt guard artifact to a concrete OCI registry.
    pub async fn publish_guard_artifact(
        &self,
        reference: &GuardPublishRef,
        artifact: GuardPublishArtifact,
        credentials: &RegistryCredentials,
    ) -> Result<GuardPublishResponse> {
        let push = self
            .client
            .push(
                reference.as_oci_reference(),
                &artifact.layers,
                artifact.config.clone(),
                &credentials.to_registry_auth(),
                Some(artifact.manifest.clone()),
            )
            .await?;

        Ok(push_response(push, artifact.manifest.config.digest))
    }
}

fn layer(data: Vec<u8>, media_type: &str, role: &str) -> ImageLayer {
    ImageLayer::new(
        data,
        media_type.to_owned(),
        Some(HashMap::from([(
            GUARD_LAYER_ROLE_ANNOTATION.to_owned(),
            role.to_owned(),
        )])),
    )
}

fn push_response(push: PushResponse, config_digest: String) -> GuardPublishResponse {
    GuardPublishResponse {
        config_url: push.config_url,
        manifest_url: push.manifest_url,
        config_digest,
    }
}
