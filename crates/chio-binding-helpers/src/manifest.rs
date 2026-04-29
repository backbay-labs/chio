use chio_core::PublicKey;
use chio_manifest::SignedManifest;
use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestVerification {
    pub structure_valid: bool,
    pub signature_valid: bool,
    pub embedded_public_key_valid: bool,
    pub embedded_public_key_matches_signer: bool,
}

pub fn parse_signed_manifest_json(input: &str) -> Result<SignedManifest> {
    Ok(serde_json::from_str(input)?)
}

pub fn signed_manifest_body_canonical_json(signed_manifest: &SignedManifest) -> Result<String> {
    chio_core::canonical_json_string(&signed_manifest.manifest).map_err(Into::into)
}

pub fn verify_signed_manifest(signed_manifest: &SignedManifest) -> Result<ManifestVerification> {
    let structure_valid = chio_manifest::validate_manifest(&signed_manifest.manifest).is_ok();
    let embedded_public_key = PublicKey::from_hex(&signed_manifest.manifest.public_key).ok();

    Ok(ManifestVerification {
        structure_valid,
        signature_valid: signed_manifest
            .signer_key
            .verify_canonical(&signed_manifest.manifest, &signed_manifest.signature)?,
        embedded_public_key_valid: embedded_public_key.is_some(),
        embedded_public_key_matches_signer: embedded_public_key
            .as_ref()
            .is_some_and(|key| key == &signed_manifest.signer_key),
    })
}

pub fn verify_signed_manifest_json(input: &str) -> Result<ManifestVerification> {
    let signed_manifest = parse_signed_manifest_json(input)?;
    verify_signed_manifest(&signed_manifest)
}

#[cfg(test)]
mod tests {
    use super::verify_signed_manifest;
    use chio_core::Keypair;
    use chio_manifest::{sign_manifest, LatencyHint, ToolDefinition, ToolManifest};

    fn sample_manifest(public_key: String) -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "srv-bindings-demo".to_string(),
            name: "Bindings Demo".to_string(),
            description: Some("Bindings manifest verification sample".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "file_read".to_string(),
                description: "Reads a file from the workspace".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                }),
                output_schema: Some(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "content": { "type": "string" }
                    }
                })),
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Fast),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key,
        }
    }

    #[test]
    fn verify_valid_signed_manifest() -> crate::Result<()> {
        let server = Keypair::from_seed(&[21u8; 32]);
        let signed_manifest =
            sign_manifest(&sample_manifest(server.public_key().to_hex()), &server)?;
        let verification = verify_signed_manifest(&signed_manifest)?;

        assert_eq!(
            verification,
            super::ManifestVerification {
                structure_valid: true,
                signature_valid: true,
                embedded_public_key_valid: true,
                embedded_public_key_matches_signer: true,
            }
        );
        Ok(())
    }
}
