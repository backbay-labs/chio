/**
 * Pure, runtime-agnostic helpers shared by the framework adapters
 * (node-http, express, fastify, elysia).
 *
 * These have no side effects and no Node or framework dependencies so that the
 * fail-closed security path stays identical across adapters instead of being
 * re-implemented per framework.
 */

import type { Verdict } from "./types.js";

/** Valid HTTP methods for Chio evaluation. */
export const VALID_METHODS = new Set<string>([
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
]);

/** HTTP status for a verdict, defaulting to 403 when none is supplied. */
export function verdictStatus(verdict: Verdict): number {
  return "http_status" in verdict ? verdict.http_status : 403;
}

/** Human-readable reason for a verdict, with a safe default. */
export function verdictReason(verdict: Verdict): string {
  return "reason" in verdict ? verdict.reason : "request was not authorized";
}

/**
 * Whether a request path matches any skip pattern.
 * String patterns match exactly; RegExp patterns match via `test`.
 */
export function shouldSkip(path: string, patterns: Array<string | RegExp>): boolean {
  for (const pattern of patterns) {
    if (typeof pattern === "string") {
      if (path === pattern) return true;
    } else {
      if (pattern.test(path)) return true;
    }
  }
  return false;
}
