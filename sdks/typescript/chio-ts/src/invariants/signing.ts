import {
  isValidEd25519PublicKeyHex,
  isValidEd25519SignatureHex,
  publicKeyHexMatches,
  signEd25519Message,
  verifyEd25519Signature,
} from "./crypto.ts";
import { canonicalizeJsonString } from "./json.ts";

export interface Utf8MessageSignature {
  public_key_hex: string;
  signature_hex: string;
}

export interface CanonicalJsonSignature extends Utf8MessageSignature {
  canonical_json: string;
}

export function isValidPublicKeyHex(value: string): boolean {
  return isValidEd25519PublicKeyHex(value);
}

export function isValidSignatureHex(value: string): boolean {
  return isValidEd25519SignatureHex(value);
}

export function signUtf8MessageEd25519(input: string, seedHex: string): Utf8MessageSignature {
  return signEd25519Message(input, seedHex);
}

export function verifyUtf8MessageEd25519(
  input: string,
  publicKeyHex: string,
  signatureHex: string,
): boolean {
  return verifyEd25519Signature(input, publicKeyHex, signatureHex);
}

export function signJsonStringEd25519(input: string, seedHex: string): CanonicalJsonSignature {
  const canonical_json = canonicalizeJsonString(input);
  const signed = signEd25519Message(canonical_json, seedHex);
  return {
    canonical_json,
    public_key_hex: signed.public_key_hex,
    signature_hex: signed.signature_hex,
  };
}

export function verifyJsonStringSignatureEd25519(
  input: string,
  publicKeyHex: string,
  signatureHex: string,
): boolean {
  return verifyEd25519Signature(canonicalizeJsonString(input), publicKeyHex, signatureHex);
}

export { publicKeyHexMatches };
