import { isValidEd25519PublicKeyHex, publicKeyHexMatches, verifyEd25519Signature } from "./crypto.ts";
import { canonicalizeJson, canonicalizeJsonString } from "./json.ts";
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
  server_tools?: Array<"computer_use" | "bash" | "text_editor">;
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

const REQUIRED_PERMISSION_FIELDS = [
  "read_paths",
  "write_paths",
  "network_hosts",
  "environment_variables",
] as const;
const REQUIRED_PERMISSION_FIELD_SET = new Set<string>(REQUIRED_PERMISSION_FIELDS);
const PRICING_MODEL_SET = new Set<string>([
  "flat",
  "per_invocation",
  "per_unit",
  "hybrid",
]);
const SIGNED_MANIFEST_FIELD_SET = new Set<string>(["manifest", "signature", "signer_key"]);
const MANIFEST_FIELD_SET = new Set<string>([
  "schema",
  "server_id",
  "name",
  "description",
  "version",
  "tools",
  "server_tools",
  "required_permissions",
  "public_key",
]);
const TOOL_FIELD_SET = new Set<string>([
  "name",
  "description",
  "input_schema",
  "output_schema",
  "pricing",
  "has_side_effects",
  "latency_hint",
]);
const PRICING_FIELD_SET = new Set<string>([
  "pricing_model",
  "base_price",
  "unit_price",
  "billing_unit",
]);
const SERVER_TOOL_SET = new Set<string>(["computer_use", "bash", "text_editor"]);
const LATENCY_HINT_SET = new Set<string>(["instant", "fast", "moderate", "slow"]);
const U64_MAX_EXCLUSIVE = 2 ** 64;

function validateManifestStructure(manifest: ToolManifest): boolean {
  if (!hasOnlyKnownKeys(manifest as unknown as Record<string, unknown>, MANIFEST_FIELD_SET)) {
    return false;
  }
  if (manifest.schema !== "chio.manifest.v1") {
    return false;
  }
  if (
    !isValidManifestTextField(manifest.server_id) ||
    !isValidManifestTextField(manifest.name) ||
    !isValidManifestTextField(manifest.version)
  ) {
    return false;
  }
  if (!Array.isArray(manifest.tools) || manifest.tools.length === 0) {
    return false;
  }
  if (typeof manifest.public_key !== "string") {
    return false;
  }
  if (!validateServerTools(manifest.server_tools)) {
    return false;
  }

  const seen = new Set<string>();
  for (const tool of manifest.tools) {
    if (!isJsonObject(tool)) {
      return false;
    }
    if (!hasOnlyKnownKeys(tool, TOOL_FIELD_SET)) {
      return false;
    }
    if (!isValidToolName(tool.name)) {
      return false;
    }
    if (seen.has(tool.name)) {
      return false;
    }
    seen.add(tool.name);
    if (!isJsonObject(tool.input_schema)) {
      return false;
    }
    if (typeof tool.description !== "string" || typeof tool.has_side_effects !== "boolean") {
      return false;
    }
    if (
      tool.output_schema !== undefined &&
      tool.output_schema !== null &&
      !isJsonObject(tool.output_schema)
    ) {
      return false;
    }
    if (!validateToolPricing(tool.pricing)) {
      return false;
    }
    if (
      tool.latency_hint !== undefined &&
      tool.latency_hint !== null &&
      (typeof tool.latency_hint !== "string" || !LATENCY_HINT_SET.has(tool.latency_hint))
    ) {
      return false;
    }
  }

  return validateRequiredPermissions(manifest.required_permissions);
}

function isValidManifestTextField(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.trim() === value &&
    !hasControlCharacter(value)
  );
}

function isValidToolName(name: unknown): name is string {
  return isValidManifestTextField(name);
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKnownKeys(value: Record<string, unknown>, knownKeys: Set<string>): boolean {
  return Object.keys(value).every((key) => knownKeys.has(key));
}

function hasControlCharacter(value: string): boolean {
  return Array.from(value).some((char) => char.charCodeAt(0) <= 0x1f || char.charCodeAt(0) === 0x7f);
}

function validateToolPricing(pricing: unknown): boolean {
  if (pricing === undefined || pricing === null) {
    return true;
  }
  if (!isJsonObject(pricing)) {
    return false;
  }
  if (!hasOnlyKnownKeys(pricing, PRICING_FIELD_SET)) {
    return false;
  }
  const model = pricing.pricing_model;
  if (typeof model !== "string" || !PRICING_MODEL_SET.has(model)) {
    return false;
  }
  switch (model) {
    case "flat":
      if (!requirePricingAmount(pricing.base_price)) {
        return false;
      }
      break;
    case "per_invocation":
    case "per_unit":
      if (!requirePricingAmount(pricing.unit_price) || !isValidManifestTextField(pricing.billing_unit)) {
        return false;
      }
      break;
    case "hybrid":
      if (
        !requirePricingAmount(pricing.base_price) ||
        !requirePricingAmount(pricing.unit_price) ||
        !isValidManifestTextField(pricing.billing_unit)
      ) {
        return false;
      }
      break;
  }
  if (!validateOptionalPricingAmount(pricing.base_price)) {
    return false;
  }
  if (!validateOptionalPricingAmount(pricing.unit_price)) {
    return false;
  }
  if (
    pricing.billing_unit !== undefined &&
    pricing.billing_unit !== null &&
    !isValidManifestTextField(pricing.billing_unit)
  ) {
    return false;
  }
  return true;
}

function requirePricingAmount(amount: unknown): boolean {
  return amount !== undefined && amount !== null && validatePricingAmount(amount);
}

function validateOptionalPricingAmount(amount: unknown): boolean {
  if (amount === undefined || amount === null) {
    return true;
  }
  return validatePricingAmount(amount);
}

function validatePricingAmount(amount: unknown): boolean {
  if (!isJsonObject(amount)) {
    return false;
  }
  return (
    isJsonU64(amount.units) &&
    isIso4217CurrencyCode(amount.currency)
  );
}

function isJsonU64(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 0 &&
    value < U64_MAX_EXCLUSIVE
  );
}

function isIso4217CurrencyCode(currency: unknown): currency is string {
  return typeof currency === "string" && /^[A-Z]{3}$/.test(currency);
}

function validateServerTools(serverTools: unknown): boolean {
  if (serverTools === undefined || serverTools === null) {
    return true;
  }
  if (!Array.isArray(serverTools)) {
    return false;
  }
  const seen = new Set<string>();
  for (const serverTool of serverTools) {
    if (
      typeof serverTool !== "string" ||
      !SERVER_TOOL_SET.has(serverTool) ||
      seen.has(serverTool)
    ) {
      return false;
    }
    seen.add(serverTool);
  }
  return true;
}

function validateRequiredPermissions(permissions: unknown): boolean {
  if (permissions === undefined || permissions === null) {
    return true;
  }
  if (!isJsonObject(permissions)) {
    return false;
  }
  for (const field of Object.keys(permissions)) {
    if (!REQUIRED_PERMISSION_FIELD_SET.has(field)) {
      return false;
    }
  }
  for (const field of REQUIRED_PERMISSION_FIELDS) {
    if (!validateRequiredPermissionValues(permissions[field])) {
      return false;
    }
  }
  return true;
}

function validateRequiredPermissionValues(values: unknown): boolean {
  if (values === undefined || values === null) {
    return true;
  }
  if (!Array.isArray(values)) {
    return false;
  }
  const seen = new Set<string>();
  for (const value of values) {
    if (!isValidManifestTextField(value) || seen.has(value)) {
      return false;
    }
    seen.add(value);
  }
  return true;
}

export function parseSignedManifestJson(input: string): SignedManifest {
  return parseJsonText(input);
}

export function signedManifestBodyCanonicalJson(signedManifest: SignedManifest): string {
  return canonicalizeJson(signedManifest.manifest);
}

function validateSignedManifestEnvelope(signedManifest: unknown): boolean {
  if (!isJsonObject(signedManifest)) {
    return false;
  }
  const keys = Object.keys(signedManifest);
  return keys.length === SIGNED_MANIFEST_FIELD_SET.size &&
    keys.every((key) => SIGNED_MANIFEST_FIELD_SET.has(key));
}

export function verifySignedManifest(signedManifest: SignedManifest): ManifestVerification {
  const envelope_valid = validateSignedManifestEnvelope(signedManifest);
  const signed_manifest_object = isJsonObject(signedManifest) ? signedManifest : undefined;
  const manifest = signed_manifest_object?.manifest;
  const manifest_object_valid = isJsonObject(manifest);
  const signature = signed_manifest_object?.signature;
  const signer_key = signed_manifest_object?.signer_key;
  const embedded_public_key = manifest_object_valid ? manifest.public_key : undefined;
  const embedded_public_key_string =
    typeof embedded_public_key === "string" ? embedded_public_key : undefined;
  const embedded_public_key_valid =
    embedded_public_key_string !== undefined &&
    isValidEd25519PublicKeyHex(embedded_public_key_string);
  const signature_valid =
    envelope_valid &&
    manifest_object_valid &&
    typeof signature === "string" &&
    typeof signer_key === "string" &&
    safelyVerifySignedManifestSignature(manifest, signer_key, signature);

  return {
    structure_valid:
      envelope_valid &&
      manifest_object_valid &&
      validateManifestStructure(manifest as ToolManifest),
    signature_valid,
    embedded_public_key_valid,
    embedded_public_key_matches_signer:
      embedded_public_key_valid &&
      typeof signer_key === "string" &&
      embedded_public_key_string !== undefined &&
      publicKeyHexMatches(embedded_public_key_string, signer_key),
  };
}

function safelyVerifySignedManifestSignature(
  manifest: Record<string, unknown>,
  signerKey: string,
  signature: string,
): boolean {
  try {
    if (containsUnsafeInteger(manifest)) {
      return false;
    }
    return verifyEd25519Signature(canonicalizeJson(manifest), signerKey, signature);
  } catch {
    return false;
  }
}

function safelyVerifySignedManifestCanonicalSignature(
  canonicalManifest: string,
  signerKey: string,
  signature: string,
): boolean {
  try {
    return verifyEd25519Signature(canonicalManifest, signerKey, signature);
  } catch {
    return false;
  }
}

function containsUnsafeInteger(value: unknown): boolean {
  if (typeof value === "number") {
    return Number.isInteger(value) && !Number.isSafeInteger(value);
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsUnsafeInteger(item));
  }
  if (isJsonObject(value)) {
    return Object.values(value).some((item) => containsUnsafeInteger(item));
  }
  return false;
}

export function verifySignedManifestJson(input: string): ManifestVerification {
  const signedManifest = parseSignedManifestJson(input);
  const verification = verifySignedManifest(signedManifest);
  const signed_manifest_object = isJsonObject(signedManifest) ? signedManifest : undefined;
  const raw_manifest = extractTopLevelJsonField(input, "manifest");
  const signature = signed_manifest_object?.signature;
  const signer_key = signed_manifest_object?.signer_key;
  const signature_valid =
    validateSignedManifestEnvelope(signedManifest) &&
    raw_manifest !== undefined &&
    typeof signature === "string" &&
    typeof signer_key === "string" &&
    safelyVerifySignedManifestCanonicalSignature(
      canonicalizeJsonString(raw_manifest),
      signer_key,
      signature,
    );
  return {
    ...verification,
    signature_valid,
  };
}

function extractTopLevelJsonField(input: string, fieldName: string): string | undefined {
  let index = skipWhitespace(input, 0);
  if (input[index] !== "{") {
    return undefined;
  }
  index += 1;
  index = skipWhitespace(input, index);
  if (input[index] === "}") {
    return undefined;
  }
  while (index < input.length) {
    index = skipWhitespace(input, index);
    if (input[index] !== "\"") {
      return undefined;
    }
    const keyStart = index;
    const keyEnd = scanJsonStringEnd(input, index);
    if (keyEnd === undefined) {
      return undefined;
    }
    let key: unknown;
    try {
      key = JSON.parse(input.slice(keyStart, keyEnd));
    } catch {
      return undefined;
    }
    index = skipWhitespace(input, keyEnd);
    if (input[index] !== ":") {
      return undefined;
    }
    const valueStart = skipWhitespace(input, index + 1);
    const valueEnd = scanJsonValueEnd(input, valueStart);
    if (valueEnd === undefined) {
      return undefined;
    }
    if (key === fieldName) {
      return input.slice(valueStart, valueEnd);
    }
    index = skipWhitespace(input, valueEnd);
    if (input[index] === ",") {
      index += 1;
      continue;
    }
    if (input[index] === "}") {
      return undefined;
    }
    return undefined;
  }
  return undefined;
}

function skipWhitespace(input: string, index: number): number {
  while (index < input.length) {
    const char = input[index];
    if (char === undefined || !/\s/.test(char)) {
      break;
    }
    index += 1;
  }
  return index;
}

function scanJsonStringEnd(input: string, start: number): number | undefined {
  if (input[start] !== "\"") {
    return undefined;
  }
  let index = start + 1;
  while (index < input.length) {
    const char = input[index];
    if (char === undefined) {
      return undefined;
    }
    if (char === "\"") {
      return index + 1;
    }
    if (char === "\\") {
      index += 2;
      continue;
    }
    if (char.charCodeAt(0) <= 0x1f) {
      return undefined;
    }
    index += 1;
  }
  return undefined;
}

function scanJsonValueEnd(input: string, start: number): number | undefined {
  const char = input[start];
  if (char === "\"") {
    return scanJsonStringEnd(input, start);
  }
  if (char === "{") {
    return scanJsonObjectEnd(input, start);
  }
  if (char === "[") {
    return scanJsonArrayEnd(input, start);
  }
  if (input.startsWith("true", start)) {
    return start + 4;
  }
  if (input.startsWith("false", start)) {
    return start + 5;
  }
  if (input.startsWith("null", start)) {
    return start + 4;
  }
  const numberMatch = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(input.slice(start));
  return numberMatch === null ? undefined : start + numberMatch[0].length;
}

function scanJsonObjectEnd(input: string, start: number): number | undefined {
  let index = start + 1;
  index = skipWhitespace(input, index);
  if (input[index] === "}") {
    return index + 1;
  }
  while (index < input.length) {
    index = skipWhitespace(input, index);
    const keyEnd = scanJsonStringEnd(input, index);
    if (keyEnd === undefined) {
      return undefined;
    }
    index = skipWhitespace(input, keyEnd);
    if (input[index] !== ":") {
      return undefined;
    }
    index = skipWhitespace(input, index + 1);
    const valueEnd = scanJsonValueEnd(input, index);
    if (valueEnd === undefined) {
      return undefined;
    }
    index = skipWhitespace(input, valueEnd);
    if (input[index] === ",") {
      index += 1;
      continue;
    }
    if (input[index] === "}") {
      return index + 1;
    }
    return undefined;
  }
  return undefined;
}

function scanJsonArrayEnd(input: string, start: number): number | undefined {
  let index = start + 1;
  index = skipWhitespace(input, index);
  if (input[index] === "]") {
    return index + 1;
  }
  while (index < input.length) {
    index = skipWhitespace(input, index);
    const valueEnd = scanJsonValueEnd(input, index);
    if (valueEnd === undefined) {
      return undefined;
    }
    index = skipWhitespace(input, valueEnd);
    if (input[index] === ",") {
      index += 1;
      continue;
    }
    if (input[index] === "]") {
      return index + 1;
    }
    return undefined;
  }
  return undefined;
}
