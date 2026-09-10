/**
 * Default identity extraction from HTTP request headers.
 *
 * Mirrors the Rust extract_caller logic in chio-api-protect/src/evaluator.rs.
 * Extracts caller identity from Authorization headers, cookies, and API keys.
 */

import { createHash } from "node:crypto";
import type { AuthMethod, CallerIdentity, IdentityExtractor } from "./types.js";

/** Compute SHA-256 hex digest of a string. */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf-8").digest("hex");
}

/**
 * Default identity extractor. Checks headers in this order:
 * 1. Authorization: Bearer <token>
 * 2. X-API-Key / x-api-key header
 * 3. Cookie header (first cookie)
 * 4. Anonymous fallback
 */
export const defaultIdentityExtractor: IdentityExtractor = (
  headers: Record<string, string | string[] | undefined>,
): CallerIdentity => {
  // Normalize header lookup (case-insensitive).
  const get = (name: string): string | undefined => {
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === lower) {
        return Array.isArray(v) ? v[0] : v;
      }
    }
    return undefined;
  };

  // 1. Bearer token
  const auth = get("authorization");
  if (auth != null) {
    const bearerMatch = auth.match(/^Bearer\s+(.+)$/i);
    if (bearerMatch != null && bearerMatch[1] != null) {
      const tokenHash = sha256Hex(bearerMatch[1]);
      const authMethod: AuthMethod = { method: "bearer", token_hash: tokenHash };
      return {
        subject: `bearer:${tokenHash.slice(0, 16)}`,
        auth_method: authMethod,
        verified: false,
      };
    }
  }

  // 2. API key
  for (const keyHeader of ["x-api-key", "X-Api-Key", "X-API-Key"]) {
    const keyValue = get(keyHeader);
    if (keyValue != null) {
      const keyHash = sha256Hex(keyValue);
      const authMethod: AuthMethod = {
        method: "api_key",
        key_name: keyHeader,
        key_hash: keyHash,
      };
      return {
        subject: `apikey:${keyHash.slice(0, 16)}`,
        auth_method: authMethod,
        verified: false,
      };
    }
  }

  // 3. Cookie
  const cookie = get("cookie");
  if (cookie != null) {
    const firstCookie = cookie.split(";")[0];
    if (firstCookie != null) {
      const parts = firstCookie.split("=");
      const cookieName = parts[0]?.trim();
      const cookieValue = parts.slice(1).join("=").trim();
      if (cookieName != null && cookieValue.length > 0) {
        const cookieHash = sha256Hex(cookieValue);
        const authMethod: AuthMethod = {
          method: "cookie",
          cookie_name: cookieName,
          cookie_hash: cookieHash,
        };
        return {
          subject: `cookie:${cookieHash.slice(0, 16)}`,
          auth_method: authMethod,
          verified: false,
        };
      }
    }
  }

  // 4. Anonymous
  return {
    subject: "anonymous",
    auth_method: { method: "anonymous" },
    verified: false,
  };
};
