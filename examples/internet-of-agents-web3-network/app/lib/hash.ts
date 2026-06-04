// SHA-256 helpers for client-side hash verification.
//
// Web Crypto is present in modern browsers and in Node 20+ via `globalThis.crypto`.

export async function sha256Hex(bytes: ArrayBuffer | Uint8Array): Promise<string> {
  const buf =
    bytes instanceof Uint8Array
      ? Uint8Array.from(bytes).buffer
      : bytes;
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const bytesOut = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < bytesOut.length; i += 1) {
    const byte = bytesOut[i] ?? 0;
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Compare a computed hex digest with a manifest-declared hash. The manifest
 * is allowed to carry either a bare hex string or a `sha256:` prefix.
 */
export function matchesManifestHash(expected: string, computedHex: string): boolean {
  const normalized = expected.startsWith("sha256:") ? expected.slice("sha256:".length) : expected;
  // Tolerate the trailing ellipsis that some placeholders used.
  const trimmed = normalized.replace(/[^0-9a-f]/gi, "").toLowerCase();
  return trimmed === computedHex.toLowerCase();
}
