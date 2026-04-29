use std::convert::TryFrom;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use chio_guard_registry::{
    expected_identity_from_config, load_guard_with_policy, AttestError, AttestVerifier,
    ExpectedIdentity, GuardArtifactConfig, GuardCache, GuardLoadEventResult, GuardLoadSource,
    GuardNetworkState, GuardOciRef, GuardOfflineLoadError, GuardOfflineLoadRequest,
    GuardPublishArtifact, GuardPublishArtifactInput, GuardPublishRef, GuardRegistryClient,
    GuardRegistryConfig, GuardRegistryError, GuardSigstoreVerifier, GuardVerificationKind,
    RegistryCredentials, Sha256Digest, VerifiedAttestation,
};
use oci_distribution::client::{Client, ClientConfig, ClientProtocol};
use oci_distribution::secrets::RegistryAuth;
use oci_distribution::Reference;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::GenericImage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Instant};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const ZOT_IMAGE: &str = "ghcr.io/project-zot/zot";
const ZOT_TAG: &str = "v2.1.10";
const ZOT_PORT: u16 = 5000;
const REPOSITORY: &str = "chio/guard-registry/zot-integration";
const TAG: &str = "suite";
const SIGNER_SUBJECT: &str =
    "https://github.com/backbay/chio/.github/workflows/release-binaries.yml@refs/tags/v1.0.0";
const OFFLINE_MISS_DIGEST: &str =
    "sha256:9999999999999999999999999999999999999999999999999999999999999999";
const WIT_BYTES: &[u8] = b"package chio:guard@0.2.0;";
const MODULE_BYTES: &[u8] = b"\0asm\x01\0\0\0zot integration module";
const MANIFEST_BYTES: &[u8] = br#"{
  "name": "zot-integration-guard",
  "version": "1.0.0",
  "wit_world": "chio:guard/guard@0.2.0",
  "wasm_path": "zot_integration.wasm"
}"#;
const BUNDLE_BYTES: &[u8] = br#"{"bundle":"zot-integration"}"#;

#[ignore = "requires a Docker daemon and pulls ghcr.io/project-zot/zot"]
#[tokio::test]
async fn zot_publish_pull_verify_and_offline_paths() -> TestResult<()> {
    let registry = start_zot_registry().await?;
    let credentials = RegistryCredentials::Anonymous;
    let client = registry.guard_client()?;
    let publish_ref = registry.publish_ref()?;
    let artifact = guard_artifact()?;

    let publish = client
        .publish_guard_artifact(&publish_ref, artifact, &credentials)
        .await?;
    assert!(publish.config_url.contains(&publish.config_digest));
    assert!(publish.manifest_url.contains(REPOSITORY));

    let digest = registry.manifest_digest().await?;
    let pull_ref = registry.pull_ref(&digest)?;
    let cache_temp = tempfile::tempdir()?;
    let cache = GuardCache::from_cache_home(cache_temp.path());
    let pull = client
        .pull_guard_to_cache(chio_guard_registry::GuardPullRequest {
            reference: &pull_ref,
            credentials: &credentials,
            cache: &cache,
        })
        .await?;

    assert_eq!(pull.registry_manifest_digest, digest);
    assert_eq!(read(&pull.cached.layout.wit_bin_path())?, WIT_BYTES);
    assert_eq!(read(&pull.cached.layout.module_wasm_path())?, MODULE_BYTES);
    assert_eq!(read(&pull.cached.layout.sigstore_bundle_json_path())?, b"");
    fs::write(pull.cached.layout.sigstore_bundle_json_path(), BUNDLE_BYTES)?;

    let expected = expected_identity();
    let verifier = StaticVerifier::allow(MODULE_BYTES, SIGNER_SUBJECT);
    let sigstore = GuardSigstoreVerifier::new(&verifier, &expected);
    let report = sigstore.verify_cached_layout_report(&pull.cached.layout)?;
    assert_eq!(report.kind, GuardVerificationKind::SigstoreOnly);

    let mut tampered = MODULE_BYTES.to_vec();
    tampered.push(b'!');
    let tampered_result = sigstore.verify_bundle(&tampered, BUNDLE_BYTES);
    assert!(matches!(
        tampered_result,
        Err(GuardRegistryError::VerifySignatureMismatch)
    ));

    let wrong_subject = StaticVerifier::wrong_subject();
    let wrong_subject_result = GuardSigstoreVerifier::new(&wrong_subject, &expected)
        .verify_bundle(MODULE_BYTES, BUNDLE_BYTES);
    assert!(matches!(
        wrong_subject_result,
        Err(GuardRegistryError::VerifyWrongSubject)
    ));

    let load = load_guard_with_policy(
        GuardOfflineLoadRequest {
            cache: &cache,
            digest: pull_ref.digest(),
            network: GuardNetworkState::Offline,
            verification: GuardVerificationKind::SigstoreOnly,
        },
        |layout| sigstore.verify_cached_layout_report(layout),
    )?;
    assert_eq!(load.event.result, GuardLoadEventResult::Allow);
    assert_eq!(load.event.source, GuardLoadSource::OfflineCache);
    assert_eq!(load.event.reason, None);

    let miss_digest = parse_digest(OFFLINE_MISS_DIGEST)?;
    let miss = load_guard_with_policy(
        GuardOfflineLoadRequest {
            cache: &cache,
            digest: &miss_digest,
            network: GuardNetworkState::Offline,
            verification: GuardVerificationKind::SigstoreOnly,
        },
        |_layout| {
            Err(GuardRegistryError::VerifyFailedClosed {
                message: "offline cache miss must not invoke verifier".to_owned(),
            })
        },
    );
    match miss {
        Err(GuardOfflineLoadError::OfflineCacheMiss { digest, event, .. }) => {
            assert_eq!(digest, OFFLINE_MISS_DIGEST);
            assert_eq!(event.result, GuardLoadEventResult::Deny);
            assert_eq!(event.source, GuardLoadSource::OfflineCache);
            assert_eq!(event.reason.as_deref(), Some("offline-cache-miss"));
        }
        other => panic!("expected offline cache miss, got {other:?}"),
    }

    Ok(())
}

struct ZotRegistry {
    registry: String,
    _container: testcontainers::ContainerAsync<GenericImage>,
}

impl ZotRegistry {
    fn guard_client(&self) -> Result<GuardRegistryClient, GuardRegistryError> {
        GuardRegistryClient::try_new(GuardRegistryConfig {
            allow_http_registries: vec![self.registry.clone()],
            ..GuardRegistryConfig::default()
        })
    }

    fn publish_ref(&self) -> Result<GuardPublishRef, GuardRegistryError> {
        format!("oci://{}/{REPOSITORY}:{TAG}", self.registry).parse::<GuardPublishRef>()
    }

    fn pull_ref(&self, digest: &str) -> Result<GuardOciRef, GuardRegistryError> {
        format!("oci://{}/{REPOSITORY}@{digest}", self.registry).parse::<GuardOciRef>()
    }

    async fn manifest_digest(&self) -> TestResult<String> {
        let reference = format!("{}/{REPOSITORY}:{TAG}", self.registry).parse::<Reference>()?;
        let client = Client::try_from(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![self.registry.clone()]),
            ..ClientConfig::default()
        })?;
        Ok(client
            .fetch_manifest_digest(&reference, &RegistryAuth::Anonymous)
            .await?)
    }
}

async fn start_zot_registry() -> TestResult<ZotRegistry> {
    let image = GenericImage::new(ZOT_IMAGE, ZOT_TAG)
        .with_exposed_port(ZOT_PORT.tcp())
        .with_wait_for(WaitFor::seconds(1));
    let container = image.start().await?;
    let host = container.get_host().await?;
    let host_port = container.get_host_port_ipv4(ZOT_PORT).await?;
    let registry = format!("{host}:{host_port}");
    wait_for_registry(&container, &registry).await?;

    Ok(ZotRegistry {
        registry,
        _container: container,
    })
}

async fn wait_for_registry(
    container: &testcontainers::ContainerAsync<GenericImage>,
    registry: &str,
) -> TestResult<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_error = None;

    while Instant::now() < deadline {
        match registry_api_ready(registry).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                sleep(Duration::from_millis(250)).await;
            }
        }
    }

    let stdout = log_text(container.stdout_to_vec().await);
    let stderr = log_text(container.stderr_to_vec().await);
    let message = format!(
        "zot registry did not accept TCP connections at {registry}; last_error={last_error:?}; stdout={stdout}; stderr={stderr}"
    );
    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, message).into())
}

async fn registry_api_ready(registry: &str) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(registry).await?;
    let request = format!("GET /v2/ HTTP/1.1\r\nHost: {registry}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    if response.starts_with(b"HTTP/1.1 200")
        || response.starts_with(b"HTTP/1.1 202")
        || response.starts_with(b"HTTP/1.1 401")
    {
        Ok(())
    } else {
        let status = String::from_utf8_lossy(&response[..response.len().min(32)]);
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("registry API not ready at {registry}: {status}"),
        ))
    }
}

fn log_text(log_result: Result<Vec<u8>, testcontainers::TestcontainersError>) -> String {
    match log_result {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) => format!("failed to read logs: {error}"),
    }
}

fn guard_artifact() -> Result<GuardPublishArtifact, GuardRegistryError> {
    GuardPublishArtifact::build(GuardPublishArtifactInput {
        wit: WIT_BYTES.to_vec(),
        module: MODULE_BYTES.to_vec(),
        manifest: MANIFEST_BYTES.to_vec(),
        config: GuardArtifactConfig::new(
            "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            5_000_000,
            16_777_216,
            "01HX0000000000000000000000",
        ),
        signer_subject: Some(SIGNER_SUBJECT.to_owned()),
    })
}

fn expected_identity() -> ExpectedIdentity
where
    ExpectedIdentity: Sized,
{
    expected_identity_from_config(
        "https://github\\.com/backbay/chio/\\.github/workflows/release-binaries\\.yml@refs/tags/v.*",
        "https://token.actions.githubusercontent.com",
    )
}

fn parse_digest(input: &str) -> Result<Sha256Digest, GuardRegistryError> {
    input.parse::<Sha256Digest>()
}

fn read(path: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(path)
}

enum VerifierMode {
    Allow {
        expected_artifact: &'static [u8],
        identity: &'static str,
    },
    WrongSubject,
}

struct StaticVerifier {
    mode: VerifierMode,
}

impl StaticVerifier {
    fn allow(expected_artifact: &'static [u8], identity: &'static str) -> Self {
        Self {
            mode: VerifierMode::Allow {
                expected_artifact,
                identity,
            },
        }
    }

    fn wrong_subject() -> Self {
        Self {
            mode: VerifierMode::WrongSubject,
        }
    }
}

impl AttestVerifier for StaticVerifier {
    fn verify_blob(
        &self,
        _artifact: &Path,
        _signature: &Path,
        _certificate: &Path,
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_blob unused".to_owned()))
    }

    fn verify_bytes(
        &self,
        _artifact: &[u8],
        _signature: &[u8],
        _certificate_pem: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        Err(AttestError::Malformed("verify_bytes unused".to_owned()))
    }

    fn verify_bundle(
        &self,
        artifact: &[u8],
        bundle_json: &[u8],
        _expected: &ExpectedIdentity,
    ) -> Result<VerifiedAttestation, AttestError> {
        match self.mode {
            VerifierMode::Allow {
                expected_artifact,
                identity,
            } => {
                if artifact != expected_artifact || bundle_json != BUNDLE_BYTES {
                    return Err(AttestError::SignatureMismatch);
                }

                Ok(VerifiedAttestation {
                    subject_digest_sha256: sha256_array(artifact),
                    certificate_identity: identity.to_owned(),
                    certificate_oidc_issuer: "https://token.actions.githubusercontent.com"
                        .to_owned(),
                    rekor_log_index: 42,
                    rekor_inclusion_verified: true,
                    signed_at: SystemTime::UNIX_EPOCH,
                })
            }
            VerifierMode::WrongSubject => Err(AttestError::IdentityMismatch),
        }
    }
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}
