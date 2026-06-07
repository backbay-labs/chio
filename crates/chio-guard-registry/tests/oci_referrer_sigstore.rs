use std::net::SocketAddr;

use chio_guard_registry::{
    GuardOciRef, GuardRegistryClient, GuardRegistryConfig, GuardRegistryError, RegistryCredentials,
    SIGSTORE_BUNDLE_MEDIA_TYPE,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const REPOSITORY: &str = "chio/guard-registry/sigstore-referrer";
const SUBJECT_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const BUNDLE_BYTES: &[u8] = br#"{"bundle":"fixture"}"#;
const OCI_ARTIFACT_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.artifact.manifest.v1+json";
const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_CONTENT_DIGEST_HEADER: &str = "Docker-Content-Digest";

#[tokio::test]
async fn pulls_sigstore_bundle_from_oci_referrer() -> TestResult<()> {
    let fixture = ReferrerFixture::valid();
    let registry = FakeRegistry::spawn(fixture).await?;
    let client = registry.client()?;
    let reference = registry.reference()?;

    let bundle = client
        .pull_sigstore_bundle_referrer(&reference, &RegistryCredentials::Anonymous)
        .await?;

    assert_eq!(bundle, Some(BUNDLE_BYTES.to_vec()));
    Ok(())
}

#[tokio::test]
async fn returns_none_when_sigstore_referrer_is_missing() -> TestResult<()> {
    let registry = FakeRegistry::spawn(ReferrerFixture::missing()).await?;
    let client = registry.client()?;
    let reference = registry.reference()?;

    let bundle = client
        .pull_sigstore_bundle_referrer(&reference, &RegistryCredentials::Anonymous)
        .await?;

    assert_eq!(bundle, None);
    Ok(())
}

#[tokio::test]
async fn rejects_sigstore_referrer_blob_descriptor_mismatch() -> TestResult<()> {
    for fault in [DescriptorFault::Size, DescriptorFault::Digest] {
        let registry = FakeRegistry::spawn(ReferrerFixture::with_fault(fault)).await?;
        let client = registry.client()?;
        let reference = registry.reference()?;

        let result = client
            .pull_sigstore_bundle_referrer(&reference, &RegistryCredentials::Anonymous)
            .await;

        match (fault, result) {
            (
                DescriptorFault::Size,
                Err(GuardRegistryError::DescriptorSizeMismatch {
                    artifact: "sigstore_bundle",
                    ..
                }),
            ) => {}
            (
                DescriptorFault::Digest,
                Err(GuardRegistryError::DescriptorDigestMismatch {
                    artifact: "sigstore_bundle",
                    ..
                }),
            ) => {}
            other => panic!("unexpected referrer descriptor result: {other:?}"),
        }
    }
    Ok(())
}

#[derive(Clone)]
struct ReferrerFixture {
    referrers_json: Vec<u8>,
    artifact_manifest_json: Vec<u8>,
    artifact_manifest_digest: String,
    bundle_bytes: Vec<u8>,
}

impl ReferrerFixture {
    fn valid() -> Self {
        Self::new(Some(BundleDescriptor {
            digest: sha256_digest(BUNDLE_BYTES),
            size: i64::try_from(BUNDLE_BYTES.len()).unwrap_or(i64::MAX),
        }))
    }

    fn missing() -> Self {
        let referrers_json = serialize_json(serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": []
        }));
        Self {
            referrers_json,
            artifact_manifest_json: Vec::new(),
            artifact_manifest_digest: sha256_digest(b"missing"),
            bundle_bytes: BUNDLE_BYTES.to_vec(),
        }
    }

    fn with_fault(fault: DescriptorFault) -> Self {
        match fault {
            DescriptorFault::Size => Self::new(Some(BundleDescriptor {
                digest: sha256_digest(BUNDLE_BYTES),
                size: i64::try_from(BUNDLE_BYTES.len()).unwrap_or(i64::MAX) + 1,
            })),
            DescriptorFault::Digest => Self::new(Some(BundleDescriptor {
                digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_owned(),
                size: i64::try_from(BUNDLE_BYTES.len()).unwrap_or(i64::MAX),
            })),
        }
    }

    fn new(bundle_descriptor: Option<BundleDescriptor>) -> Self {
        let bundle_descriptor = match bundle_descriptor {
            Some(descriptor) => descriptor,
            None => BundleDescriptor {
                digest: sha256_digest(BUNDLE_BYTES),
                size: i64::try_from(BUNDLE_BYTES.len()).unwrap_or(i64::MAX),
            },
        };
        let artifact_manifest_json = serialize_json(serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_ARTIFACT_MANIFEST_MEDIA_TYPE,
            "artifactType": SIGSTORE_BUNDLE_MEDIA_TYPE,
            "blobs": [{
                "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
                "digest": bundle_descriptor.digest,
                "size": bundle_descriptor.size
            }]
        }));
        let artifact_manifest_digest = sha256_digest(&artifact_manifest_json);
        let referrers_json = serialize_json(serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [{
                "mediaType": OCI_ARTIFACT_MANIFEST_MEDIA_TYPE,
                "artifactType": SIGSTORE_BUNDLE_MEDIA_TYPE,
                "digest": artifact_manifest_digest,
                "size": artifact_manifest_json.len()
            }]
        }));

        Self {
            referrers_json,
            artifact_manifest_json,
            artifact_manifest_digest,
            bundle_bytes: BUNDLE_BYTES.to_vec(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum DescriptorFault {
    Size,
    Digest,
}

struct BundleDescriptor {
    digest: String,
    size: i64,
}

struct FakeRegistry {
    authority: String,
    _server: JoinHandle<()>,
}

impl FakeRegistry {
    async fn spawn(fixture: ReferrerFixture) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let authority = authority(address);
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _peer)) = listener.accept().await {
                let fixture = fixture.clone();
                tokio::spawn(async move {
                    let response = match read_request_target(&mut stream).await {
                        Ok(target) => response_for_target(&fixture, &target),
                        Err(error) => http_response(
                            "400 Bad Request",
                            "text/plain",
                            format!("bad request: {error}").into_bytes(),
                            None,
                        ),
                    };
                    let _ = stream.write_all(&response).await;
                });
            }
        });

        Ok(Self {
            authority,
            _server: server,
        })
    }

    fn client(&self) -> Result<GuardRegistryClient, GuardRegistryError> {
        GuardRegistryClient::try_new(GuardRegistryConfig {
            allow_http_registries: vec![self.authority.clone()],
            ..GuardRegistryConfig::default()
        })
    }

    fn reference(&self) -> Result<GuardOciRef, GuardRegistryError> {
        format!("oci://{}/{REPOSITORY}@{SUBJECT_DIGEST}", self.authority).parse()
    }
}

impl Drop for FakeRegistry {
    fn drop(&mut self) {
        self._server.abort();
    }
}

async fn read_request_target(stream: &mut tokio::net::TcpStream) -> std::io::Result<String> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > 32 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&request);
    let first_line = match text.lines().next() {
        Some(line) => line,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "empty request",
            ));
        }
    };
    let mut parts = first_line.split_whitespace();
    let _method = parts.next();
    match parts.next() {
        Some(target) => Ok(target.to_owned()),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing request target",
        )),
    }
}

fn response_for_target(fixture: &ReferrerFixture, target: &str) -> Vec<u8> {
    let path = target.split('?').next().unwrap_or(target);
    if path.contains("/referrers/") {
        return http_response(
            "200 OK",
            OCI_IMAGE_INDEX_MEDIA_TYPE,
            fixture.referrers_json.clone(),
            None,
        );
    }
    if path.contains("/manifests/") {
        return http_response(
            "200 OK",
            OCI_ARTIFACT_MANIFEST_MEDIA_TYPE,
            fixture.artifact_manifest_json.clone(),
            Some((
                DOCKER_CONTENT_DIGEST_HEADER,
                &fixture.artifact_manifest_digest,
            )),
        );
    }
    if path.contains("/blobs/") {
        return http_response(
            "200 OK",
            SIGSTORE_BUNDLE_MEDIA_TYPE,
            fixture.bundle_bytes.clone(),
            None,
        );
    }
    http_response(
        "404 Not Found",
        "text/plain",
        format!("no fixture route for {path}").into_bytes(),
        None,
    )
}

fn http_response(
    status: &str,
    content_type: &str,
    body: Vec<u8>,
    extra_header: Option<(&str, &str)>,
) -> Vec<u8> {
    let mut headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some((name, value)) = extra_header {
        headers.push_str(name);
        headers.push_str(": ");
        headers.push_str(value);
        headers.push_str("\r\n");
    }
    headers.push_str("\r\n");

    let mut response = headers.into_bytes();
    response.extend_from_slice(&body);
    response
}

fn authority(address: SocketAddr) -> String {
    format!("{}:{}", address.ip(), address.port())
}

fn serialize_json(value: serde_json::Value) -> Vec<u8> {
    match serde_json::to_vec(&value) {
        Ok(bytes) => bytes,
        Err(error) => panic!("fixture JSON should serialize: {error}"),
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
