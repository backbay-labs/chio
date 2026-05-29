import { isValidEd25519PublicKeyHex, publicKeyHexMatches, verifyEd25519Signature } from "./crypto.ts";
import { canonicalizeJson } from "./json.ts";
import { parseJsonText } from "./errors.ts";

export interface MonetaryAmount {
  units: number;
  currency: string;
}

export type PricingModel = "flat" | "per_invocation" | "per_unit" | "hybrid";

export interface ToolPricing {
  pricing_model: PricingModel;
  base_price?: MonetaryAmount;
  unit_price?: MonetaryAmount;
  billing_unit?: string;
}

export interface ToolManifest {
  schema: string;
  server_id: string;
  name: string;
  description?: string;
  version: string;
  tools: Array<{
    name: string;
    description: string;
    input_schema: unknown;
    output_schema?: unknown;
    pricing?: ToolPricing;
    has_side_effects: boolean;
    latency_hint?: "instant" | "fast" | "moderate" | "slow";
  }>;
  required_permissions?: {
    read_paths?: string[];
    write_paths?: string[];
    network_hosts?: string[];
    environment_variables?: string[];
  };
  public_key: string;
}

export interface SignedManifest {
  manifest: ToolManifest;
  signature: string;
  signer_key: string;
}

export interface ManifestVerification {
  structure_valid: boolean;
  signature_valid: boolean;
  embedded_public_key_valid: boolean;
  embedded_public_key_matches_signer: boolean;
}

function validateManifestStructure(manifest: ToolManifest): boolean {
  if (manifest.schema !== "chio.manifest.v1") {
    return false;
  }
  if (manifest.tools.length === 0) {
    return false;
  }

  const seen = new Set<string>();
  for (const tool of manifest.tools) {
    if (seen.has(tool.name)) {
      return false;
    }
    seen.add(tool.name);
  }

  return true;
}

export function parseSignedManifestJson(input: string): SignedManifest {
  return parseJsonText(input);
}

export function signedManifestBodyCanonicalJson(signedManifest: SignedManifest): string {
  return canonicalizeJson(signedManifest.manifest);
}

export function verifySignedManifest(signedManifest: SignedManifest): ManifestVerification {
  const embedded_public_key_valid = isValidEd25519PublicKeyHex(signedManifest.manifest.public_key);

  return {
    structure_valid: validateManifestStructure(signedManifest.manifest),
    signature_valid: verifyEd25519Signature(
      signedManifestBodyCanonicalJson(signedManifest),
      signedManifest.signer_key,
      signedManifest.signature,
    ),
    embedded_public_key_valid,
    embedded_public_key_matches_signer:
      embedded_public_key_valid &&
      publicKeyHexMatches(signedManifest.manifest.public_key, signedManifest.signer_key),
  };
}

export function verifySignedManifestJson(input: string): ManifestVerification {
  return verifySignedManifest(parseSignedManifestJson(input));
}
