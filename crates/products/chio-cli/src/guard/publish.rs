use std::fs;
use std::path::Path;

use base64::Engine;
use chio_guard_registry::{
    ExpectedIdentity, GuardArtifactConfig, GuardCache, GuardOciRef, GuardPublishArtifact,
    GuardPublishArtifactInput, GuardPublishRef, GuardPullRequest, GuardPullSigstoreBundleSource,
    GuardRegistryClient, GuardRegistryConfig, RegistryCredentials, SigstoreVerifier,
    GUARD_ARTIFACT_MEDIA_TYPE, GUARD_CONFIG_MEDIA_TYPE, GUARD_WIT_WORLD,
};
use chio_wasm_guards::blocklist::{GuardDigestBlocklist, E_GUARD_DIGEST_BLOCKLISTED};
use chio_wasm_guards::manifest::GuardManifest;
use sha2::{Digest, Sha256};

use crate::CliError;

use super::{guard_io_error, guard_yaml_error};

pub(crate) struct GuardPublishCommand<'a> {
    pub project_dir: &'a Path,
    pub reference: &'a str,
    pub wit_path: &'a Path,
    pub signer_public_key: Option<&'a str>,
    pub signer_subject: Option<&'a str>,
    pub fuel_limit: u64,
    pub memory_limit_bytes: u64,
    pub epoch_id_seed: &'a str,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub allow_http_registry: Vec<String>,
}

pub(crate) fn cmd_guard_publish(command: GuardPublishCommand<'_>) -> Result<(), CliError> {
    let preflight = guard_publish_preflight(command.project_dir)?;
    let wit_bytes = fs::read(command.wit_path).map_err(|e| {
        guard_io_error(format!(
            "failed to read WIT file {}: {e}",
            command.wit_path.display()
        ))
    })?;

    let signer_public_key =
        resolve_signer_public_key(command.signer_public_key, &preflight.manifest)?;
    let artifact_config = GuardArtifactConfig::new(
        signer_public_key,
        command.fuel_limit,
        command.memory_limit_bytes,
        command.epoch_id_seed,
    );
    let artifact = GuardPublishArtifact::build(GuardPublishArtifactInput {
        wit: wit_bytes,
        module: preflight.wasm_bytes,
        manifest: preflight.manifest_content.into_bytes(),
        config: artifact_config,
        signer_subject: command.signer_subject.map(str::to_owned),
    })
    .map_err(|e| CliError::guard_error(e.to_string()))?;

    let reference = command
        .reference
        .parse::<GuardPublishRef>()
        .map_err(|e| CliError::guard_error(e.to_string()))?;
    let credentials = registry_credentials(command.username, command.password);
    let client = GuardRegistryClient::try_new(GuardRegistryConfig {
        allow_http_registries: command.allow_http_registry,
        ..GuardRegistryConfig::default()
    })
    .map_err(|e| CliError::guard_error(e.to_string()))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::cli_other_error(format!("failed to create publish runtime: {e}")))?;
    let response = runtime
        .block_on(client.publish_guard_artifact(&reference, artifact, &credentials))
        .map_err(|e| CliError::guard_error(e.to_string()))?;

    println!("published guard artifact");
    println!("reference:         {reference}");
    println!("artifact_type:     {GUARD_ARTIFACT_MEDIA_TYPE}");
    println!("config_media_type: {GUARD_CONFIG_MEDIA_TYPE}");
    println!("config_digest:     {}", response.config_digest);
    println!("config_url:        {}", response.config_url);
    println!("manifest_url:      {}", response.manifest_url);

    Ok(())
}

pub(super) struct GuardPublishPreflight {
    pub(super) manifest_content: String,
    pub(super) manifest: GuardManifest,
    pub(super) wasm_bytes: Vec<u8>,
}

pub(super) fn guard_publish_preflight(
    project_dir: &Path,
) -> Result<GuardPublishPreflight, CliError> {
    let manifest_path = project_dir.join("guard-manifest.yaml");
    let manifest_content = fs::read_to_string(&manifest_path)
        .map_err(|e| guard_io_error(format!("failed to read {}: {e}", manifest_path.display())))?;
    let manifest: GuardManifest = serde_yml::from_str(&manifest_content)
        .map_err(|e| guard_yaml_error(format!("failed to parse guard-manifest.yaml: {e}")))?;

    let wit_world = manifest.wit_world.as_deref().unwrap_or(GUARD_WIT_WORLD);
    if wit_world != GUARD_WIT_WORLD {
        return Err(CliError::guard_error(format!(
            "guard publish requires wit_world {GUARD_WIT_WORLD}, got {wit_world}"
        )));
    }

    validate_publish_wasm_sha256(&manifest.wasm_sha256)?;

    let wasm_path = project_dir.join(Path::new(&manifest.wasm_path));
    let wasm_bytes = fs::read(&wasm_path).map_err(|e| {
        guard_io_error(format!(
            "failed to read wasm file {}: {e}",
            wasm_path.display()
        ))
    })?;
    let actual_sha256 = wasm_sha256_hex(&wasm_bytes);
    if actual_sha256 != manifest.wasm_sha256 {
        return Err(CliError::guard_error(format!(
            "guard publish preflight rejected guard-manifest.yaml: wasm_sha256 mismatch: expected {}, actual {}",
            manifest.wasm_sha256, actual_sha256
        )));
    }

    Ok(GuardPublishPreflight {
        manifest_content,
        manifest,
        wasm_bytes,
    })
}

fn validate_publish_wasm_sha256(value: &str) -> Result<(), CliError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::guard_error(
            "guard publish preflight rejected guard-manifest.yaml: wasm_sha256 must be lowercase hex SHA-256 digest (64 characters)"
                .to_string(),
        ));
    }
    if value.bytes().any(|byte| matches!(byte, b'A'..=b'F')) {
        return Err(CliError::guard_error(
            "guard publish preflight rejected guard-manifest.yaml: wasm_sha256 must be lowercase hex SHA-256 digest (64 characters)"
                .to_string(),
        ));
    }
    Ok(())
}

fn wasm_sha256_hex(wasm_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(wasm_bytes))
}

pub(crate) struct GuardPullCommand<'a> {
    pub reference: &'a str,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub allow_http_registry: Vec<String>,
    pub sigstore_bundle: Option<&'a Path>,
    pub sigstore_identity_regex: Option<&'a str>,
    pub sigstore_oidc_issuer: Option<&'a str>,
}

pub(crate) fn cmd_guard_pull(command: GuardPullCommand<'_>) -> Result<(), CliError> {
    let reference = command
        .reference
        .parse::<GuardOciRef>()
        .map_err(|e| CliError::guard_error(e.to_string()))?;
    let blocklist = GuardDigestBlocklist::from_environment()
        .map_err(|e| CliError::guard_error(format!("failed to load guard blocklist: {e}")))?;
    if blocklist
        .is_blocklisted(reference.digest().as_str())
        .map_err(|e| CliError::guard_error(format!("failed to check guard blocklist: {e}")))?
    {
        return Err(CliError::guard_error(format!(
            "{E_GUARD_DIGEST_BLOCKLISTED}: guard digest {} is blocklisted",
            reference.digest()
        )));
    }
    let credentials = registry_credentials(command.username, command.password);
    let cache = GuardCache::from_environment().map_err(|e| CliError::guard_error(e.to_string()))?;
    let sigstore_bundle = match command.sigstore_bundle {
        Some(path) => Some(std::fs::read(path).map_err(|e| {
            CliError::cli_io_error(format!(
                "failed to read Sigstore bundle {}: {e}",
                path.display()
            ))
        })?),
        None => None,
    };
    let sigstore_policy = match (
        command.sigstore_identity_regex,
        command.sigstore_oidc_issuer,
    ) {
        (None, None) => None,
        (Some(identity), Some(issuer)) => Some(ExpectedIdentity {
            certificate_identity_regexp: identity.to_string(),
            certificate_oidc_issuer: issuer.to_string(),
        }),
        _ => {
            return Err(CliError::guard_error(
                "--sigstore-identity-regex and --sigstore-oidc-issuer must be supplied together"
                    .to_string(),
            ));
        }
    };
    let sigstore_verifier = if sigstore_policy.is_some() {
        Some(SigstoreVerifier::with_embedded_root().map_err(|e| {
            CliError::guard_error(format!("failed to load Sigstore trust root: {e}"))
        })?)
    } else {
        None
    };
    let client = GuardRegistryClient::try_new(GuardRegistryConfig {
        allow_http_registries: command.allow_http_registry,
        ..GuardRegistryConfig::default()
    })
    .map_err(|e| CliError::guard_error(e.to_string()))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::cli_other_error(format!("failed to create pull runtime: {e}")))?;
    let response = runtime
        .block_on(
            client.pull_guard_to_cache(GuardPullRequest {
                reference: &reference,
                credentials: &credentials,
                cache: &cache,
                sigstore_bundle_json: sigstore_bundle.as_deref(),
                sigstore_verifier: sigstore_verifier
                    .as_ref()
                    .map(|verifier| verifier as &dyn chio_guard_registry::AttestVerifier),
                sigstore_expected_identity: sigstore_policy.as_ref(),
            }),
        )
        .map_err(|e| CliError::guard_error(e.to_string()))?;

    println!("pulled guard artifact");
    println!("reference:        {reference}");
    println!("digest:           {}", response.cached.digest);
    println!("manifest_digest:  {}", response.registry_manifest_digest);
    println!(
        "cache_dir:        {}",
        response.cached.layout.directory().display()
    );
    println!(
        "manifest_json:    {}",
        response.cached.layout.manifest_json_path().display()
    );
    println!(
        "config_json:      {}",
        response.cached.layout.config_json_path().display()
    );
    println!(
        "wit_bin:          {}",
        response.cached.layout.wit_bin_path().display()
    );
    println!(
        "module_wasm:      {}",
        response.cached.layout.module_wasm_path().display()
    );
    println!(
        "guard_manifest:   {}",
        response.cached.layout.guard_manifest_json_path().display()
    );
    let sigstore_bundle_path = response.cached.layout.sigstore_bundle_json_path();
    if sigstore_bundle_path.exists() {
        println!("sigstore_bundle:  {}", sigstore_bundle_path.display());
        match response.sigstore_bundle_source {
            Some(GuardPullSigstoreBundleSource::CallerProvided) => {
                if response.sigstore_verified {
                    println!(
                        "sigstore_status:  verified caller-provided bundle before cache admission"
                    );
                } else {
                    println!("sigstore_status:  cached caller-provided bundle bytes without verification policy");
                }
            }
            Some(GuardPullSigstoreBundleSource::OciReferrer) => {
                if response.sigstore_verified {
                    println!(
                        "sigstore_status:  verified OCI referrer bundle before cache admission"
                    );
                } else {
                    println!("sigstore_status:  cached OCI referrer bundle bytes without verification policy");
                }
            }
            None => {
                println!("sigstore_status:  cached bundle bytes without source metadata");
            }
        }
    } else {
        println!(
            "sigstore_bundle:  not cached (no local bundle supplied and no OCI Sigstore referrer found)"
        );
    }

    Ok(())
}

fn resolve_signer_public_key(
    explicit: Option<&str>,
    manifest: &GuardManifest,
) -> Result<String, CliError> {
    let Some(value) = explicit.or(manifest.signer_public_key.as_deref()) else {
        return Err(CliError::guard_error(
            "guard publish requires --signer-public-key or signer_public_key in guard-manifest.yaml"
                .to_string(),
        ));
    };

    if value.starts_with("ed25519:") {
        return Ok(value.to_owned());
    }

    let decoded = hex::decode(value).map_err(|e| {
        CliError::guard_error(format!(
            "signer public key must be ed25519:<base64> or hex-encoded Ed25519 bytes: {e}"
        ))
    })?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(decoded);
    Ok(format!("ed25519:{encoded}"))
}

fn registry_credentials(username: Option<&str>, password: Option<&str>) -> RegistryCredentials {
    match (username, password) {
        (Some(username), Some(password)) => RegistryCredentials::Basic {
            username: username.to_owned(),
            password: password.to_owned(),
        },
        _ => RegistryCredentials::Anonymous,
    }
}
