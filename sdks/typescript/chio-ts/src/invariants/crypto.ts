import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signMessage,
  verify as verifySignature,
} from "node:crypto";

import { ChioInvariantError } from "./errors.ts";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// SPKI prefix bytes preceding a raw 65-byte uncompressed SEC1 point (0x04 || X || Y)
// for the prime256v1 (P-256) named curve. Encodes the SubjectPublicKeyInfo header:
// SEQUENCE { AlgorithmIdentifier { id-ecPublicKey, prime256v1 }, BIT STRING ... }.
const P256_SPKI_PREFIX = Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d030107034200",
  "hex",
);

// SPKI prefix bytes for the secp384r1 (P-384) named curve preceding a raw 97-byte
// uncompressed SEC1 point.
const P384_SPKI_PREFIX = Buffer.from(
  "3076301006072a8648ce3d020106052b81040022036200",
  "hex",
);

const P256_RAW_POINT_BYTES = 65;
const P384_RAW_POINT_BYTES = 97;

function normalizeHex(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}

function hexToBuffer(
  hex: string,
  expectedBytes: number,
  code: "invalid_hex" | "invalid_public_key" | "invalid_signature",
): Buffer {
  const normalized = normalizeHex(hex);
  if (!/^[0-9a-f]+$/i.test(normalized)) {
    throw new ChioInvariantError(code, "value is not valid hexadecimal");
  }
  if (normalized.length !== expectedBytes * 2) {
    throw new ChioInvariantError(code, `expected ${expectedBytes} bytes of hex, got ${normalized.length / 2}`);
  }
  return Buffer.from(normalized, "hex");
}

function createEd25519PrivateKey(seedHex: string) {
  try {
    return createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, hexToBuffer(seedHex, 32, "invalid_hex")]),
      format: "der",
      type: "pkcs8",
    });
  } catch (cause) {
    if (cause instanceof ChioInvariantError) {
      throw cause;
    }
    throw new ChioInvariantError("invalid_hex", "value is not a valid Ed25519 seed", { cause });
  }
}

function createEd25519PublicKey(publicKeyHex: string) {
  try {
    return createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, hexToBuffer(publicKeyHex, 32, "invalid_public_key")]),
      format: "der",
      type: "spki",
    });
  } catch (cause) {
    if (cause instanceof ChioInvariantError) {
      throw cause;
    }
    throw new ChioInvariantError("invalid_public_key", "value is not a valid Ed25519 public key", { cause });
  }
}

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

export function isValidEd25519PublicKeyHex(publicKeyHex: string): boolean {
  try {
    hexToBuffer(publicKeyHex, 32, "invalid_public_key");
    return true;
  } catch {
    return false;
  }
}

export function isValidEd25519SignatureHex(signatureHex: string): boolean {
  try {
    hexToBuffer(signatureHex, 64, "invalid_signature");
    return true;
  } catch {
    return false;
  }
}

export function publicKeyHexMatches(left: string, right: string): boolean {
  return normalizeHex(left) === normalizeHex(right);
}

function publicKeyHexFromSeedHex(seedHex: string): string {
  const privateKey = createEd25519PrivateKey(seedHex);
  const publicKeyDer = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });
  return Buffer.from(publicKeyDer).subarray(ED25519_SPKI_PREFIX.length).toString("hex");
}

export function signEd25519Message(
  message: string | Buffer,
  seedHex: string,
): { public_key_hex: string; signature_hex: string } {
  const privateKey = createEd25519PrivateKey(seedHex);
  const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8");
  return {
    public_key_hex: publicKeyHexFromSeedHex(seedHex),
    signature_hex: Buffer.from(signMessage(null, messageBuffer, privateKey)).toString("hex"),
  };
}

export function verifyEd25519Signature(
  message: string | Buffer,
  publicKeyHex: string,
  signatureHex: string,
): boolean {
  const signatureBytes = hexToBuffer(signatureHex, 64, "invalid_signature");
  const key = createEd25519PublicKey(publicKeyHex);
  return verifySignature(
    null,
    Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8"),
    key,
    signatureBytes,
  );
}

function hexBodyToBuffer(hexBody: string): Buffer {
  if (hexBody.length === 0 || hexBody.length % 2 !== 0) {
    throw new ChioInvariantError(
      "invalid_signature",
      "signature hex body must be a non-empty even-length string",
    );
  }
  if (!/^[0-9a-f]+$/i.test(hexBody)) {
    throw new ChioInvariantError("invalid_signature", "signature hex body is not valid hexadecimal");
  }
  return Buffer.from(hexBody, "hex");
}

function createEcdsaPublicKey(
  publicKeyHex: string,
  curve: "P-256" | "P-384",
): ReturnType<typeof createPublicKey> {
  const rawHex = normalizeHex(publicKeyHex);
  if (!/^[0-9a-f]+$/i.test(rawHex)) {
    throw new ChioInvariantError("invalid_public_key", "public key is not valid hexadecimal");
  }

  const rawBytes = Buffer.from(rawHex, "hex");
  const expectedRawLen = curve === "P-256" ? P256_RAW_POINT_BYTES : P384_RAW_POINT_BYTES;
  const prefix = curve === "P-256" ? P256_SPKI_PREFIX : P384_SPKI_PREFIX;

  // Accept either a raw uncompressed SEC1 point (0x04 || X || Y) which we wrap in
  // the curve's fixed SPKI prefix, or a full DER-encoded SPKI blob (callers pass
  // either form depending on key origin).
  let spki: Buffer;
  if (rawBytes.length === expectedRawLen && rawBytes[0] === 0x04) {
    spki = Buffer.concat([prefix, rawBytes]);
  } else if (rawBytes.length > expectedRawLen) {
    spki = rawBytes;
  } else {
    throw new ChioInvariantError(
      "invalid_public_key",
      `value is not a valid ${curve} public key (expected ${expectedRawLen} raw bytes or SPKI DER)`,
    );
  }

  try {
    return createPublicKey({
      key: spki,
      format: "der",
      type: "spki",
    });
  } catch (cause) {
    throw new ChioInvariantError(
      "invalid_public_key",
      `value is not a valid ${curve} public key`,
      { cause },
    );
  }
}

function verifyEcdsaSignature(
  message: Buffer,
  publicKeyHex: string,
  signatureHexBody: string,
  curve: "P-256" | "P-384",
): boolean {
  const hashAlgorithm = curve === "P-256" ? "sha256" : "sha384";
  const signatureDer = hexBodyToBuffer(signatureHexBody);
  const key = createEcdsaPublicKey(publicKeyHex, curve);
  try {
    return verifySignature(
      hashAlgorithm,
      message,
      { key, dsaEncoding: "der" },
      signatureDer,
    );
  } catch (cause) {
    throw new ChioInvariantError(
      "invalid_signature",
      `value is not a valid ${curve} signature`,
      { cause },
    );
  }
}

export function verifyChioSignature(
  signedBytes: string | Buffer,
  signature: string,
  publicKey: string,
): boolean {
  const message = Buffer.isBuffer(signedBytes) ? signedBytes : Buffer.from(signedBytes, "utf8");

  if (signature.startsWith("p256:")) {
    return verifyEcdsaSignature(message, publicKey, signature.slice("p256:".length), "P-256");
  }
  if (signature.startsWith("p384:")) {
    return verifyEcdsaSignature(message, publicKey, signature.slice("p384:".length), "P-384");
  }
  if (signature.startsWith("hybrid:")) {
    throw new ChioInvariantError(
      "invalid_signature",
      "hybrid post-quantum signatures are not supported by this SDK build",
    );
  }
  // No recognised prefix means a bare 128-char hex Ed25519 signature; the
  // existing verifier already enforces the 64-byte length.
  return verifyEd25519Signature(message, publicKey, signature);
}
