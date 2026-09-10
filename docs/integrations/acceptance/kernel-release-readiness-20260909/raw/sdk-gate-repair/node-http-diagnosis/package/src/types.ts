/**
 * Core types for the Chio HTTP substrate.
 *
 * These types mirror the Rust chio-http-core crate and define the contract
 * between TypeScript middleware and the Chio sidecar kernel.
 */

// -- HTTP Method --

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

/** Whether an HTTP method is considered side-effect-free. */
export function isMethodSafe(method: HttpMethod): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

// -- Auth Method (tagged union matching Rust serde) --

export type AuthMethod =
  | { method: "bearer"; token_hash: string }
  | { method: "api_key"; key_name: string; key_hash: string }
  | { method: "cookie"; cookie_name: string; cookie_hash: string }
  | { method: "mtls_certificate"; subject_dn: string; fingerprint: string }
  | { method: "anonymous" };

// -- Caller Identity --

export interface CallerIdentity {
  /** Stable identifier for the caller (e.g., user ID, service account). */
  subject: string;
  /** How the caller authenticated. */
  auth_method: AuthMethod;
  /** Whether this identity has been cryptographically verified. */
  verified: boolean;
  /** Optional tenant or organization. */
  tenant?: string | undefined;
  /** Optional agent identifier when the caller is an AI agent. */
  agent_id?: string | undefined;
}

export type ModelSafetyTier = "low" | "standard" | "high" | "restricted";

export interface ModelMetadata {
  model_id: string;
  safety_tier?: ModelSafetyTier | undefined;
  provider?: string | undefined;
}

// -- Verdict (tagged union matching Rust serde) --

export type Verdict =
  | { verdict: "allow" }
  | { verdict: "deny"; reason: string; guard: string; http_status: number }
  | { verdict: "cancel"; reason: string }
  | { verdict: "incomplete"; reason: string };

export function isAllowed(verdict: Verdict): verdict is { verdict: "allow" } {
  return verdict.verdict === "allow";
}

export function isDenied(verdict: Verdict): verdict is { verdict: "deny"; reason: string; guard: string; http_status: number } {
  return verdict.verdict === "deny";
}

// -- Guard Evidence --

export interface GuardEvidence {
  guard_name: string;
  verdict: boolean;
  details?: string | undefined;
}

// -- HTTP Receipt --

export interface HttpReceipt {
  id: string;
  request_id: string;
  route_pattern: string;
  method: HttpMethod;
  caller_identity_hash: string;
  session_id?: string | undefined;
  verdict: Verdict;
  receipt_kind: "mediated_decision" | "trace_observation" | "advisory_evaluation";
  boundary_class: "prevent" | "detect_only" | "advisory_only";
  observation_outcome?: "observed" | "evaluated" | "dropped" | undefined;
  tool_origin: "caller_executed" | "host_executed_provider_reported" | "host_executed_unmediated";
  redaction_mode: "none" | "summary" | "redacted";
  actor_chain?: Array<Record<string, unknown>> | undefined;
  evidence: GuardEvidence[];
  // Chio evaluation-time HTTP status; allow receipts may be signed before the
  // downstream response exists.
  response_status: number;
  timestamp: number;
  content_hash: string;
  policy_hash: string;
  trust_level: "mediated" | "verified" | "advisory";
  capability_id?: string | undefined;
  metadata?: unknown;
  kernel_key: string;
  signature: string;
}

export function isAuthorizedHttpReceipt(receipt: HttpReceipt): boolean {
  return receipt.receipt_kind === "mediated_decision"
    && receipt.boundary_class === "prevent"
    && receipt.observation_outcome === undefined
    && receipt.trust_level === "mediated"
    && isAllowed(receipt.verdict);
}

export interface VerifyReceiptResponse {
  signature_valid: boolean;
  signer_trusted: boolean;
  receipt_id_valid: boolean;
  parameter_hash_valid: boolean;
  receipt_kind: string;
  boundary_class: string;
  trust_level: string;
  result: string;
  authorized: boolean;
  signer_key_hex: string;
  ok: boolean;
}

export function isVerifyReceiptResponse(value: unknown): value is VerifyReceiptResponse {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return typeof record.signature_valid === "boolean"
    && typeof record.signer_trusted === "boolean"
    && typeof record.receipt_id_valid === "boolean"
    && typeof record.parameter_hash_valid === "boolean"
    && typeof record.receipt_kind === "string"
    && typeof record.boundary_class === "string"
    && typeof record.trust_level === "string"
    && typeof record.result === "string"
    && typeof record.authorized === "boolean"
    && typeof record.signer_key_hex === "string"
    && typeof record.ok === "boolean";
}

export function isAuthoritativeVerification(
  verification: VerifyReceiptResponse,
  receipt?: HttpReceipt | undefined,
): boolean {
  return verification.ok
    && verification.authorized
    && verification.signer_trusted
    && verification.signature_valid
    && verification.receipt_id_valid
    && verification.parameter_hash_valid
    && verification.receipt_kind === "mediated_decision"
    && verification.boundary_class === "prevent"
    && verification.trust_level === "mediated"
    && verification.result === "allow"
    && (receipt == null || isAuthorizedHttpReceipt(receipt));
}

// -- Chio HTTP Request (sent to sidecar for evaluation) --

export interface ChioHttpRequest {
  request_id: string;
  method: HttpMethod;
  route_pattern: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  caller: CallerIdentity;
  body_hash?: string | undefined;
  body_length: number;
  session_id?: string | undefined;
  capability_id?: string | undefined;
  /** Optional sidecar tool-server identity for synthetic tool-call evaluations. */
  tool_server?: string | undefined;
  /** Optional sidecar tool name for synthetic tool-call evaluations. */
  tool_name?: string | undefined;
  /** Optional structured tool-call arguments for synthetic sidecar evaluations. */
  arguments?: unknown;
  model_metadata?: ModelMetadata | undefined;
  timestamp: number;
}

// -- Sidecar evaluate response --

export interface EvaluateResponse {
  verdict: Verdict;
  receipt?: HttpReceipt | undefined;
  evidence: GuardEvidence[];
}

/** Explicit passthrough state reserved for degraded-state integrations. */
export interface ChioPassthrough {
  mode: "allow_without_receipt";
  error: typeof CHIO_ERROR_CODES.SIDECAR_UNREACHABLE;
  message: string;
}

// -- Chio middleware configuration --

export interface ChioConfig {
  /**
   * URL of the Chio sidecar kernel (e.g., "http://127.0.0.1:9090").
   * Defaults to CHIO_SIDECAR_URL env var or "http://127.0.0.1:9090".
   */
  sidecarUrl?: string | undefined;

  /**
   * Path to chio.yaml config file. When provided, the sidecar reads
   * route patterns and policies from this file.
   */
  config?: string | undefined;

  /**
   * Custom identity extractor. Override the default header-based extraction.
   */
  identityExtractor?: IdentityExtractor | undefined;

  /**
   * Route pattern resolver. Maps a raw request path to a pattern
   * (e.g., "/pets/42" -> "/pets/{petId}").
   */
  routePatternResolver?: RoutePatternResolver | undefined;

  /** Reserved no-op option. The middleware always denies sidecar errors. */
  onSidecarError?: "deny" | "allow" | undefined;

  /**
   * Timeout in milliseconds for sidecar HTTP calls. Default: 5000.
   */
  timeoutMs?: number | undefined;

  /**
   * Headers to forward to the sidecar for policy evaluation.
   * Default: ["content-type", "content-length"].
   */
  forwardHeaders?: string[] | undefined;
}

/** Extract caller identity from an incoming HTTP request. */
export type IdentityExtractor = (headers: Record<string, string | string[] | undefined>) => CallerIdentity;

/** Resolve a raw request path to a route pattern. */
export type RoutePatternResolver = (method: HttpMethod, path: string) => string;

// -- Chio error codes for HTTP responses --

export const CHIO_ERROR_CODES = {
  ACCESS_DENIED: "chio_access_denied",
  SIDECAR_UNREACHABLE: "chio_sidecar_unreachable",
  SIDECAR_UNAVAILABLE: "chio_sidecar_unavailable",
  EVALUATION_FAILED: "chio_evaluation_failed",
  INVALID_RECEIPT: "chio_invalid_receipt",
  TIMEOUT: "chio_timeout",
} as const;

export type ChioErrorCode = typeof CHIO_ERROR_CODES[keyof typeof CHIO_ERROR_CODES];

/** Structured error response body. */
export interface ChioErrorResponse {
  error: ChioErrorCode;
  message: string;
  receipt_id?: string | undefined;
  suggestion?: string | undefined;
}
