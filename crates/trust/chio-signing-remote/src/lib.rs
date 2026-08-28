//! Remote signing implementations for hosted Chio deployments.
//!
//! Both backends pin an explicit public key and key version. A successful
//! transport response is accepted only after local strict signature
//! verification over the exact input bytes.

use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chio_core::error::Result;
use chio_core::{
    canonical_json_bytes, sha256, Error, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

const HTTP_SIGN_REQUEST_SCHEMA: &str = "chio.signing.http-request.v1";
const HTTP_SIGN_RESPONSE_SCHEMA: &str = "chio.signing.http-response.v1";
const MAX_SIGNING_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Clone)]
struct RemoteSecret(Arc<str>);

impl RemoteSecret {
    fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control) {
            return Err(signing_error("remote signer credential is invalid"));
        }
        Ok(Self(Arc::from(value)))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RemoteSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Pinned configuration shared by remote signing implementations.
#[derive(Clone, Debug)]
pub struct RemoteSigningKey {
    key_handle: String,
    key_version: u32,
    public_key: PublicKey,
}

impl RemoteSigningKey {
    pub fn new(
        key_handle: impl Into<String>,
        key_version: u32,
        public_key: PublicKey,
    ) -> Result<Self> {
        let key_handle = key_handle.into();
        if key_version == 0
            || key_handle.is_empty()
            || key_handle.len() > 256
            || !key_handle.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || public_key.algorithm() != SigningAlgorithm::Ed25519
            || public_key.is_weak_ed25519()
        {
            return Err(signing_error("remote signing key configuration is invalid"));
        }
        Ok(Self {
            key_handle,
            key_version,
            public_key,
        })
    }

    #[must_use]
    pub fn key_handle(&self) -> &str {
        &self.key_handle
    }

    #[must_use]
    pub const fn key_version(&self) -> u32 {
        self.key_version
    }

    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Generic Chio HTTP signing backend.
#[derive(Clone)]
pub struct HttpSigningBackend {
    base_url: String,
    key: RemoteSigningKey,
    bearer_token: RemoteSecret,
    http: ureq::Agent,
}

impl fmt::Debug for HttpSigningBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpSigningBackend")
            .field("base_url", &self.base_url)
            .field("key", &self.key)
            .field("bearer_token", &self.bearer_token)
            .finish_non_exhaustive()
    }
}

impl HttpSigningBackend {
    pub fn new(
        base_url: impl Into<String>,
        key: RemoteSigningKey,
        bearer_token: impl Into<String>,
    ) -> Result<Self> {
        let base_url = validate_base_url(&base_url.into())?;
        Ok(Self {
            base_url,
            key,
            bearer_token: RemoteSecret::new(bearer_token)?,
            http: build_agent(Duration::from_secs(5)),
        })
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http = build_agent(timeout);
        self
    }

    fn sign_endpoint(&self) -> String {
        format!(
            "{}/v1/signing-keys/{}/sign",
            self.base_url,
            self.key.key_handle()
        )
    }
}

impl SigningBackend for HttpSigningBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.key.public_key.clone()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
        validate_message(message)?;
        let binding = HttpSignBinding {
            key_handle: self.key.key_handle(),
            key_version: self.key.key_version(),
            algorithm: SigningAlgorithm::Ed25519,
            message_sha256: sha256(message).to_hex(),
            message_base64: BASE64_STANDARD.encode(message),
        };
        let request_id = binding_digest(&binding)?;
        let request = HttpSignRequest {
            schema: HTTP_SIGN_REQUEST_SCHEMA,
            request_id: &request_id,
            binding: &binding,
        };
        let response: HttpSignResponse = send_json(
            self.http.post(&self.sign_endpoint()).set(
                "Authorization",
                &format!("Bearer {}", self.bearer_token.expose()),
            ),
            &request,
        )?;
        if response.schema != HTTP_SIGN_RESPONSE_SCHEMA
            || response.request_id != request_id
            || response.key_handle != self.key.key_handle()
            || response.key_version != self.key.key_version()
            || response.algorithm != SigningAlgorithm::Ed25519
            || response.message_sha256 != binding.message_sha256
        {
            return Err(signing_error("remote signer response binding is invalid"));
        }
        verified_signature(&self.key.public_key, message, &response.signature)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HttpSignBinding<'a> {
    key_handle: &'a str,
    key_version: u32,
    algorithm: SigningAlgorithm,
    message_sha256: String,
    message_base64: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HttpSignRequest<'a> {
    schema: &'static str,
    request_id: &'a str,
    binding: &'a HttpSignBinding<'a>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HttpSignResponse {
    schema: String,
    request_id: String,
    key_handle: String,
    key_version: u32,
    algorithm: SigningAlgorithm,
    message_sha256: String,
    signature: String,
}

/// HashiCorp Vault Transit Ed25519 signing backend.
#[derive(Clone)]
pub struct VaultTransitSigningBackend {
    base_url: String,
    mount: String,
    key: RemoteSigningKey,
    token: RemoteSecret,
    namespace: Option<String>,
    http: ureq::Agent,
}

impl fmt::Debug for VaultTransitSigningBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultTransitSigningBackend")
            .field("base_url", &self.base_url)
            .field("mount", &self.mount)
            .field("key", &self.key)
            .field("token", &self.token)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl VaultTransitSigningBackend {
    pub fn new(
        base_url: impl Into<String>,
        mount: impl Into<String>,
        key: RemoteSigningKey,
        token: impl Into<String>,
    ) -> Result<Self> {
        let base_url = validate_base_url(&base_url.into())?;
        let mount = validate_path_segment(&mount.into(), "Vault Transit mount")?;
        Ok(Self {
            base_url,
            mount,
            key,
            token: RemoteSecret::new(token)?,
            namespace: None,
            http: build_agent(Duration::from_secs(5)),
        })
    }

    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Result<Self> {
        let namespace = namespace.into();
        if namespace.is_empty() || namespace.len() > 256 || namespace.chars().any(char::is_control)
        {
            return Err(signing_error("Vault namespace is invalid"));
        }
        self.namespace = Some(namespace);
        Ok(self)
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http = build_agent(timeout);
        self
    }

    /// Verify that Vault still exposes the configured version and pinned key.
    pub fn verify_key(&self) -> Result<()> {
        let endpoint = format!(
            "{}/v1/{}/keys/{}",
            self.base_url,
            self.mount,
            self.key.key_handle()
        );
        let response: VaultKeyResponse =
            read_json(self.vault_headers(self.http.get(&endpoint)).call())?;
        let version = self.key.key_version().to_string();
        let public_key = response
            .data
            .keys
            .get(&version)
            .ok_or_else(|| signing_error("Vault does not expose the pinned key version"))?;
        let decoded = BASE64_STANDARD
            .decode(public_key.public_key.as_bytes())
            .map_err(|_| signing_error("Vault returned an invalid public key"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| signing_error("Vault returned an invalid public key"))?;
        let remote = PublicKey::from_bytes(&bytes)?;
        if remote != self.key.public_key {
            return Err(signing_error(
                "Vault public key does not match the configured pin",
            ));
        }
        Ok(())
    }

    fn vault_headers(&self, mut request: ureq::Request) -> ureq::Request {
        request = request.set("X-Vault-Token", self.token.expose());
        if let Some(namespace) = self.namespace.as_deref() {
            request = request.set("X-Vault-Namespace", namespace);
        }
        request
    }
}

impl SigningBackend for VaultTransitSigningBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.key.public_key.clone()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
        validate_message(message)?;
        let endpoint = format!(
            "{}/v1/{}/sign/{}",
            self.base_url,
            self.mount,
            self.key.key_handle()
        );
        let request = VaultSignRequest {
            input: BASE64_STANDARD.encode(message),
            key_version: self.key.key_version(),
            prehashed: false,
        };
        let response: VaultSignResponse =
            send_json(self.vault_headers(self.http.post(&endpoint)), &request)?;
        let prefix = format!("vault:v{}:", self.key.key_version());
        let encoded = response
            .data
            .signature
            .strip_prefix(&prefix)
            .ok_or_else(|| signing_error("Vault signature key version is invalid"))?;
        let bytes = BASE64_STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| signing_error("Vault returned an invalid signature"))?;
        let bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|_| signing_error("Vault returned an invalid signature"))?;
        let signature = Signature::from_bytes(&bytes);
        if !self.key.public_key.verify_strict(message, &signature) {
            return Err(signing_error("Vault signature failed local verification"));
        }
        Ok(signature)
    }
}

#[derive(Serialize)]
struct VaultSignRequest {
    input: String,
    key_version: u32,
    prehashed: bool,
}

#[derive(Deserialize)]
struct VaultSignResponse {
    data: VaultSignatureData,
}

#[derive(Deserialize)]
struct VaultSignatureData {
    signature: String,
}

#[derive(Deserialize)]
struct VaultKeyResponse {
    data: VaultKeyData,
}

#[derive(Deserialize)]
struct VaultKeyData {
    keys: std::collections::BTreeMap<String, VaultVersionedPublicKey>,
}

#[derive(Deserialize)]
struct VaultVersionedPublicKey {
    public_key: String,
}

fn validate_base_url(raw: &str) -> Result<String> {
    let parsed = Url::parse(raw).map_err(|_| signing_error("remote signer URL is invalid"))?;
    let loopback_http = parsed.scheme() == "http"
        && parsed.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if (parsed.scheme() != "https" && !loopback_http)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
    {
        return Err(signing_error("remote signer URL is invalid"));
    }
    Ok(raw.trim_end_matches('/').to_owned())
}

fn validate_path_segment(value: &str, _label: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(signing_error("remote signer path segment is invalid"));
    }
    Ok(value.to_owned())
}

fn validate_message(message: &[u8]) -> Result<()> {
    if message.is_empty() || message.len() > MAX_SIGNING_MESSAGE_BYTES {
        return Err(signing_error("remote signing message size is invalid"));
    }
    Ok(())
}

fn verified_signature(public_key: &PublicKey, message: &[u8], raw: &str) -> Result<Signature> {
    let signature = Signature::from_hex(raw)?;
    if !public_key.verify_strict(message, &signature) {
        return Err(signing_error("remote signature failed local verification"));
    }
    Ok(signature)
}

fn binding_digest<T: Serialize>(value: &T) -> Result<String> {
    let canonical = canonical_json_bytes(value)?;
    Ok(sha256(&canonical).to_hex())
}

fn build_agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .redirects(0)
        .build()
}

fn send_json<B: Serialize, T: DeserializeOwned>(request: ureq::Request, body: &B) -> Result<T> {
    let payload = serde_json::to_value(body)?;
    read_json(request.send_json(payload))
}

fn read_json<T: DeserializeOwned>(
    response: std::result::Result<ureq::Response, ureq::Error>,
) -> Result<T> {
    let response = response.map_err(|_| signing_error("remote signer request failed"))?;
    let mut reader = response.into_reader().take(MAX_RESPONSE_BYTES + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| signing_error("remote signer response could not be read"))?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(signing_error("remote signer response is too large"));
    }
    serde_json::from_slice(&bytes).map_err(|_| signing_error("remote signer response is invalid"))
}

fn signing_error(message: &str) -> Error {
    Error::InvalidSignature(message.to_owned())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use chio_core::{Keypair, SigningBackend};
    use chio_test_support::prelude::*;

    use super::*;

    #[test]
    fn generic_http_signer_verifies_exact_bytes_and_binding() {
        let keypair = Keypair::from_seed(&[31_u8; 32]);
        let message = b"canonical finding bytes";
        let binding = HttpSignBinding {
            key_handle: "finding-listing",
            key_version: 7,
            algorithm: SigningAlgorithm::Ed25519,
            message_sha256: sha256(message).to_hex(),
            message_base64: BASE64_STANDARD.encode(message),
        };
        let request_id = binding_digest(&binding).test_unwrap();
        let (base_url, request_rx, server) = spawn_json_server(serde_json::json!({
            "schema": HTTP_SIGN_RESPONSE_SCHEMA,
            "requestId": request_id,
            "keyHandle": "finding-listing",
            "keyVersion": 7,
            "algorithm": "ed25519",
            "messageSha256": sha256(message).to_hex(),
            "signature": keypair.sign(message).to_hex()
        }));
        let backend = HttpSigningBackend::new(
            base_url,
            RemoteSigningKey::new("finding-listing", 7, keypair.public_key()).test_unwrap(),
            "remote-secret",
        )
        .test_unwrap();

        let signature = backend.sign_bytes(message).test_unwrap();
        assert!(backend.public_key().verify_strict(message, &signature));
        let request = request_rx.recv().test_unwrap();
        assert!(request.starts_with("POST /v1/signing-keys/finding-listing/sign HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer remote-secret"));
        assert!(request.contains(HTTP_SIGN_REQUEST_SCHEMA));
        server.join().test_unwrap();
    }

    #[test]
    fn generic_http_signer_rejects_response_substitution() {
        let keypair = Keypair::from_seed(&[32_u8; 32]);
        let message = b"signed bytes";
        let binding = HttpSignBinding {
            key_handle: "finding-venue",
            key_version: 2,
            algorithm: SigningAlgorithm::Ed25519,
            message_sha256: sha256(message).to_hex(),
            message_base64: BASE64_STANDARD.encode(message),
        };
        let request_id = binding_digest(&binding).test_unwrap();
        let (base_url, _request_rx, server) = spawn_json_server(serde_json::json!({
            "schema": HTTP_SIGN_RESPONSE_SCHEMA,
            "requestId": request_id,
            "keyHandle": "finding-venue",
            "keyVersion": 3,
            "algorithm": "ed25519",
            "messageSha256": sha256(message).to_hex(),
            "signature": keypair.sign(message).to_hex()
        }));
        let backend = HttpSigningBackend::new(
            base_url,
            RemoteSigningKey::new("finding-venue", 2, keypair.public_key()).test_unwrap(),
            "remote-secret",
        )
        .test_unwrap();

        assert!(backend.sign_bytes(message).is_err());
        server.join().test_unwrap();
    }

    #[test]
    fn vault_signer_pins_version_and_verifies_signature() {
        let keypair = Keypair::from_seed(&[33_u8; 32]);
        let message = b"vault canonical bytes";
        let encoded_signature = BASE64_STANDARD.encode(keypair.sign(message).to_bytes());
        let (base_url, request_rx, server) = spawn_json_server(serde_json::json!({
            "request_id": "vault-request-4",
            "lease_id": "",
            "renewable": false,
            "data": {
                "signature": format!("vault:v4:{encoded_signature}"),
                "key_version": 4
            },
            "warnings": null,
            "auth": null,
            "mount_type": "transit"
        }));
        let backend = VaultTransitSigningBackend::new(
            base_url,
            "transit",
            RemoteSigningKey::new("finding-status", 4, keypair.public_key()).test_unwrap(),
            "vault-token",
        )
        .test_unwrap();

        let signature = backend.sign_bytes(message).test_unwrap();
        assert!(backend.public_key().verify_strict(message, &signature));
        let request = request_rx.recv().test_unwrap();
        assert!(request.starts_with("POST /v1/transit/sign/finding-status HTTP/1.1"));
        assert!(request.contains("X-Vault-Token: vault-token"));
        assert!(request.contains("\"key_version\":4"));
        assert!(request.contains("\"prehashed\":false"));
        server.join().test_unwrap();
    }

    #[test]
    fn vault_key_probe_rejects_a_different_public_key() {
        let configured = Keypair::from_seed(&[34_u8; 32]);
        let returned = Keypair::from_seed(&[35_u8; 32]);
        let (base_url, _request_rx, server) = spawn_json_server(serde_json::json!({
            "request_id": "vault-key-request-9",
            "data": {
                "allow_plaintext_backup": false,
                "deletion_allowed": false,
                "derived": false,
                "exportable": false,
                "keys": {
                    "9": {
                        "creation_time": "2026-08-28T00:00:00Z",
                        "name": "ed25519",
                        "public_key": BASE64_STANDARD.encode(returned.public_key().as_bytes())
                    }
                },
                "latest_version": 9,
                "min_available_version": 0,
                "min_decryption_version": 1,
                "min_encryption_version": 0,
                "name": "finding-audit",
                "supports_decryption": false,
                "supports_derivation": false,
                "supports_encryption": false,
                "supports_signing": true,
                "type": "ed25519"
            },
            "warnings": null,
            "auth": null,
            "mount_type": "transit"
        }));
        let backend = VaultTransitSigningBackend::new(
            base_url,
            "transit",
            RemoteSigningKey::new("finding-audit", 9, configured.public_key()).test_unwrap(),
            "vault-token",
        )
        .test_unwrap();

        assert!(backend.verify_key().is_err());
        server.join().test_unwrap();
    }

    #[test]
    fn production_remote_signer_requires_https() {
        let keypair = Keypair::from_seed(&[36_u8; 32]);
        let key = RemoteSigningKey::new("finding-listing", 1, keypair.public_key()).test_unwrap();
        assert!(HttpSigningBackend::new("http://example.com", key, "token").is_err());
    }

    fn spawn_json_server(
        body: serde_json::Value,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
        let address = listener.local_addr().test_unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let body = body.to_string();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().test_unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .test_unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2048];
            let mut header_end = None;
            let mut content_length = 0_usize;
            loop {
                let read = stream.read(&mut buffer).test_unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if header_end.is_none() {
                    header_end = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|position| position + 4);
                    if let Some(end) = header_end {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        content_length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                    }
                }
                if header_end.is_some_and(|end| request.len() >= end + content_length) {
                    break;
                }
            }
            request_tx
                .send(String::from_utf8_lossy(&request).into_owned())
                .test_unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).test_unwrap();
        });
        (format!("http://{address}"), request_rx, server)
    }
}
