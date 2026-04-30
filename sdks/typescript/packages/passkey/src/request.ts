// Stub for T1 scaffold; T2 fills in the requestCapability implementation
// (navigator.credentials.get + fetch to the issuer).

import { parseCapabilityToken, type PasskeyCapabilityShape } from './parse.js';

export interface RequestCapabilityOptions {
  rpId: string;
  audience: string;
  scopes: string[];
  issuerUrl: string;
  fetchImpl?: typeof fetch;
  credentials?: CredentialsContainer;
}

export type PasskeyCapability = PasskeyCapabilityShape;

/**
 * Placeholder for M10.P3.T2. The full call sequence is documented there.
 * T1 only needs the symbol exported so package consumers can pin against
 * the shape.
 */
export async function requestCapability(
  _options: RequestCapabilityOptions,
): Promise<PasskeyCapability> {
  void parseCapabilityToken; // hold the import live for T1
  throw new Error('requestCapability is implemented by M10.P3.T2');
}
