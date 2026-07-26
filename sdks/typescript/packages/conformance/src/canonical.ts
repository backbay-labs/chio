/**
 * Canonical JSON serialization (RFC 8785).
 *
 * Chio requires canonical JSON for all signed payloads. This module
 * implements the same canonical JSON as the Rust kernel so that
 * TypeScript-generated payloads produce byte-identical results.
 *
 * RFC 8785 rules:
 * - Object keys sorted lexicographically
 * - No whitespace between tokens
 * - Numbers as shortest representation
 * - Strings with minimal escaping
 * - No trailing commas
 */

/**
 * Produce RFC 8785 canonical JSON from a value.
 * Object keys are sorted lexicographically. No extra whitespace.
 */
export function canonicalJsonString(value: unknown): string {
  return canonicalize(value);
}

/**
 * Produce RFC 8785 canonical JSON bytes (UTF-8).
 */
export function canonicalJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJsonString(value));
}

function canonicalize(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    // RFC 8785: use shortest representation
    if (!Number.isFinite(value)) {
      throw new Error(`non-finite numbers are not valid JSON: ${value}`);
    }
    return JSON.stringify(value);
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalize(item));
    return `[${items.join(",")}]`;
  }

  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const entries: string[] = [];
    for (const key of keys) {
      const v = obj[key];
      if (v === undefined) {
        // Skip undefined values (matches Rust serde behavior with skip_serializing_if)
        continue;
      }
      entries.push(`${JSON.stringify(key)}:${canonicalize(v)}`);
    }
    return `{${entries.join(",")}}`;
  }

  throw new Error(`unsupported type for canonical JSON: ${typeof value}`);
}
