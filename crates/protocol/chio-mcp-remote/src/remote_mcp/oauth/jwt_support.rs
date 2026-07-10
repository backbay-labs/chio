use super::*;

impl JwtVerificationKeySource {
    pub(super) fn verify(
        &self,
        alg: JwtSignatureAlgorithm,
        header: &JwtHeader,
        signed_input: &[u8],
        signature: &[u8],
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<bool, Response> {
        match self {
            Self::Static(public_key) => {
                if alg != JwtSignatureAlgorithm::EdDsa {
                    return Err(unauthorized_bearer_response(
                        "JWT bearer token uses unsupported alg for configured static key",
                        protected_resource_metadata,
                    ));
                }
                Ok(verify_ed25519_jwt_signature(
                    public_key,
                    signed_input,
                    signature,
                ))
            }
            Self::Jwks(keys) => {
                let public_key =
                    keys.resolve(header.kid.as_deref(), alg, protected_resource_metadata)?;
                Ok(public_key.verify(alg, signed_input, signature))
            }
        }
    }
}

impl JwtJwksKeySet {
    fn resolve<'a>(
        &'a self,
        kid: Option<&str>,
        alg: JwtSignatureAlgorithm,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<&'a JwtResolvedJwkPublicKey, Response> {
        if let Some(kid) = kid {
            let key = self.keys_by_kid.get(kid).ok_or_else(|| {
                unauthorized_bearer_response(
                    "JWT bearer kid is not trusted",
                    protected_resource_metadata,
                )
            })?;
            if key.supports_alg(alg) {
                return Ok(key);
            }
            return Err(unauthorized_bearer_response(
                "trusted JWT key does not support the requested alg",
                protected_resource_metadata,
            ));
        }
        let mut compatible = self
            .keys_by_kid
            .values()
            .chain(self.anonymous_keys.iter())
            .filter(|key| key.supports_alg(alg));
        let Some(first) = compatible.next() else {
            return Err(unauthorized_bearer_response(
                "identity provider exposes no trusted key for the requested alg",
                protected_resource_metadata,
            ));
        };
        if compatible.next().is_none() {
            return Ok(first);
        }
        Err(unauthorized_bearer_response(
            "JWT bearer token missing kid for multi-key identity provider",
            protected_resource_metadata,
        ))
    }
}

impl JwtResolvedJwkPublicKey {
    fn supports_alg(&self, alg: JwtSignatureAlgorithm) -> bool {
        if let Some(alg_hint) = self.alg_hint.as_deref() {
            if alg_hint != alg.as_str() {
                return false;
            }
        }
        matches!(
            (&self.key, alg),
            (
                JwtResolvedPublicKey::Ed25519(_),
                JwtSignatureAlgorithm::EdDsa
            ) | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Rs256)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Rs384)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Rs512)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Ps256)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Ps384)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Ps512)
                | (JwtResolvedPublicKey::P256(_), JwtSignatureAlgorithm::Es256)
                | (JwtResolvedPublicKey::P384(_), JwtSignatureAlgorithm::Es384)
        )
    }

    pub(super) fn verify(&self, alg: JwtSignatureAlgorithm, signed_input: &[u8], signature: &[u8]) -> bool {
        if !self.supports_alg(alg) {
            return false;
        }
        match (&self.key, alg) {
            (JwtResolvedPublicKey::Ed25519(public_key), JwtSignatureAlgorithm::EdDsa) => {
                verify_ed25519_jwt_signature(public_key, signed_input, signature)
            }
            (JwtResolvedPublicKey::P256(public_key), JwtSignatureAlgorithm::Es256) => {
                P256Signature::from_slice(signature)
                    .ok()
                    .and_then(|signature| public_key.verify(signed_input, &signature).ok())
                    .is_some()
            }
            (JwtResolvedPublicKey::P384(public_key), JwtSignatureAlgorithm::Es384) => {
                P384Signature::from_slice(signature)
                    .ok()
                    .and_then(|signature| public_key.verify(signed_input, &signature).ok())
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Rs256) => {
                RsaPkcs1v15Signature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPkcs1v15VerifyingKey::<Sha256>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Rs384) => {
                RsaPkcs1v15Signature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPkcs1v15VerifyingKey::<sha2::Sha384>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Rs512) => {
                RsaPkcs1v15Signature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPkcs1v15VerifyingKey::<sha2::Sha512>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Ps256) => {
                RsaPssSignature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPssVerifyingKey::<Sha256>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Ps384) => {
                RsaPssSignature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPssVerifyingKey::<sha2::Sha384>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Ps512) => {
                RsaPssSignature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPssVerifyingKey::<sha2::Sha512>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            _ => false,
        }
    }
}

impl JwtClaims {
    pub(super) fn scopes(&self) -> Vec<String> {
        let mut scopes = self
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .filter(|scope| !scope.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        scopes.extend(self.scp.iter().cloned());
        scopes.sort();
        scopes.dedup();
        scopes
    }

    pub(super) fn includes_audience(&self, expected: &str) -> bool {
        match &self.aud {
            Some(JwtAudience::Single(audience)) => audience == expected,
            Some(JwtAudience::Multiple(audiences)) => audiences.iter().any(|aud| aud == expected),
            None => false,
        }
    }

    pub(super) fn includes_audience_or_resource(&self, expected: &str) -> bool {
        self.includes_audience(expected) || self.resource.as_deref() == Some(expected)
    }

    pub(super) fn primary_audience(&self) -> Option<String> {
        match &self.aud {
            Some(JwtAudience::Single(audience)) => Some(audience.clone()),
            Some(JwtAudience::Multiple(audiences)) => audiences.first().cloned(),
            None => None,
        }
    }
}

pub(super) fn decode_jwt_parts(
    token: &str,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
) -> Result<(JwtHeader, JwtClaims, String, Vec<u8>), Response> {
    let mut parts = token.split('.');
    let Some(header_b64) = parts.next() else {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    };
    let Some(payload_b64) = parts.next() else {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    };
    let Some(signature_b64) = parts.next() else {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    };
    if parts.next().is_some() {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    }

    let header: JwtHeader =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| {
            unauthorized_bearer_response("invalid JWT header", protected_resource_metadata)
        })?)
        .map_err(|_| {
            unauthorized_bearer_response("invalid JWT header", protected_resource_metadata)
        })?;
    let claims: JwtClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| {
            unauthorized_bearer_response("invalid JWT payload", protected_resource_metadata)
        })?)
        .map_err(|_| {
            unauthorized_bearer_response("invalid JWT payload", protected_resource_metadata)
        })?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|_| {
        unauthorized_bearer_response("invalid JWT signature", protected_resource_metadata)
    })?;
    Ok((
        header,
        claims,
        format!("{header_b64}.{payload_b64}"),
        signature_bytes,
    ))
}
