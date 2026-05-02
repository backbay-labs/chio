import { nativeChio } from './NativeChio.js';

export type JsonString = string;
export type HexString = string;

export type VerifiedCapability = {
  id: string;
  subjectHex: string;
  issuerHex: string;
  scopeJson: string;
  issuedAt: number;
  expiresAt: number;
  evaluatedAt: number;
};

export type PortablePassportMetadata = {
  subject: string;
  issuerHex: string;
  issuedAt: number;
  expiresAt: number;
  evaluatedAt: number;
  payloadCanonicalHex: string;
};

export async function evaluate(requestJson: JsonString): Promise<JsonString> {
  return nativeChio().evaluate(requestJson);
}

export async function signReceipt(
  bodyJson: JsonString,
  signingSeedHex: HexString,
): Promise<JsonString> {
  return nativeChio().signReceipt(bodyJson, signingSeedHex);
}

export async function verifyCapability(
  tokenJson: JsonString,
  authorityPubHex: HexString,
): Promise<VerifiedCapability> {
  return nativeChio().verifyCapability(
    tokenJson,
    authorityPubHex,
  ) as Promise<VerifiedCapability>;
}

export async function verifyPassport(
  envelopeJson: JsonString,
  issuerPubHex: HexString,
  nowSecs: number,
): Promise<PortablePassportMetadata> {
  return nativeChio().verifyPassport(
    envelopeJson,
    issuerPubHex,
    nowSecs,
  ) as Promise<PortablePassportMetadata>;
}

export async function attestAppAttest(
  keyId: string,
  challengeHex: HexString,
): Promise<JsonString> {
  return nativeChio().attestAppAttest(keyId, challengeHex);
}

export async function attestPlayIntegrity(nonceHex: HexString): Promise<JsonString> {
  return nativeChio().attestPlayIntegrity(nonceHex);
}

export async function verifyMobileReceipt(
  receiptJson: JsonString,
  evidenceJson: JsonString,
): Promise<JsonString> {
  return nativeChio().verifyMobileReceipt(receiptJson, evidenceJson);
}

export type { ChioNativeModule } from './NativeChio.js';
