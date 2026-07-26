use chio_core::crypto::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Deserializer, Serialize};

use super::validation::{validate_positive, validate_text};
use super::ChannelError;

const CHANNEL_SIGNATURE_DOMAIN: &str = "chio.channel.signature.v1";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelSignaturePayloadV1<'a, T> {
    domain: &'static str,
    signer_id: &'a str,
    key_epoch: u64,
    signer_key: &'a PublicKey,
    body: &'a T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelSignatureV1 {
    pub signer_id: String,
    pub key_epoch: u64,
    #[serde(deserialize_with = "deserialize_canonical_public_key")]
    pub signer_key: PublicKey,
    #[serde(deserialize_with = "deserialize_canonical_signature")]
    pub signature: Signature,
}

pub(super) fn deserialize_canonical_public_key<'de, D>(
    deserializer: D,
) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let key = PublicKey::from_hex(&encoded).map_err(serde::de::Error::custom)?;
    if key.to_hex() != encoded {
        return Err(serde::de::Error::custom("noncanonical public key"));
    }
    Ok(key)
}

pub(super) fn deserialize_canonical_signature<'de, D>(
    deserializer: D,
) -> Result<Signature, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let signature = Signature::from_hex(&encoded).map_err(serde::de::Error::custom)?;
    if signature.to_hex() != encoded {
        return Err(serde::de::Error::custom("noncanonical signature"));
    }
    Ok(signature)
}

impl ChannelSignatureV1 {
    pub fn sign<T: Serialize>(
        body: &T,
        signer_id: String,
        key_epoch: u64,
        keypair: &Keypair,
    ) -> Result<Self, ChannelError> {
        validate_text("signer_id", &signer_id)?;
        validate_positive("signer_key_epoch", key_epoch)?;
        let signer_key = keypair.public_key();
        let payload = ChannelSignaturePayloadV1 {
            domain: CHANNEL_SIGNATURE_DOMAIN,
            signer_id: &signer_id,
            key_epoch,
            signer_key: &signer_key,
            body,
        };
        let (signature, _) = keypair
            .sign_canonical(&payload)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
        Ok(Self {
            signer_id,
            key_epoch,
            signer_key,
            signature,
        })
    }

    pub fn verify<T: Serialize>(
        &self,
        body: &T,
        expected_signer_id: &str,
        expected_key_epoch: u64,
        expected_key: &PublicKey,
    ) -> Result<(), ChannelError> {
        validate_text("signer_id", &self.signer_id)?;
        validate_positive("signer_key_epoch", self.key_epoch)?;
        if self.signer_id != expected_signer_id
            || self.key_epoch != expected_key_epoch
            || &self.signer_key != expected_key
        {
            return Err(ChannelError::AuthorityVerification);
        }
        let payload = ChannelSignaturePayloadV1 {
            domain: CHANNEL_SIGNATURE_DOMAIN,
            signer_id: &self.signer_id,
            key_epoch: self.key_epoch,
            signer_key: &self.signer_key,
            body,
        };
        if !self
            .signer_key
            .verify_canonical(&payload, &self.signature)
            .map_err(|_| ChannelError::AuthorityVerification)?
        {
            return Err(ChannelError::AuthorityVerification);
        }
        Ok(())
    }
}
