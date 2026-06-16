/**
 * Chio sidecar HTTP client.
 *
 * Communicates with the Chio Rust kernel running as a localhost sidecar.
 * The sidecar exposes a POST /chio/evaluate endpoint that accepts an
 * ChioHttpRequest and returns an EvaluateResponse with a signed receipt.
 */

import {
  CHIO_ERROR_CODES,
  isAllowed,
  isAuthoritativeVerification,
  isAuthorizedHttpReceipt,
  isVerifyReceiptResponse,
} from "./types.js";
import type {
  ChioConfig,
  ChioHttpRequest,
  EvaluateResponse,
  HttpReceipt,
  VerifyReceiptResponse,
  Verdict,
} from "./types.js";

/** Error thrown when the sidecar is unreachable or returns an error. */
export class SidecarError extends Error {
  readonly code: string;
  readonly statusCode: number | undefined;

  constructor(code: string, message: string, statusCode?: number) {
    super(message);
    this.name = "SidecarError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

/** Resolve the sidecar URL from config or environment. */
export function resolveSidecarUrl(config: ChioConfig): string {
  if (config.sidecarUrl != null) {
    return config.sidecarUrl.replace(/\/+$/, "");
  }
  const envUrl = process.env["CHIO_SIDECAR_URL"];
  if (envUrl != null && envUrl.length > 0) {
    return envUrl.replace(/\/+$/, "");
  }
  return "http://127.0.0.1:9090";
}

/**
 * Chio sidecar client. Sends evaluation requests to the Rust kernel
 * over localhost HTTP and returns signed receipts.
 */
export class ChioSidecarClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(config: ChioConfig) {
    this.baseUrl = resolveSidecarUrl(config);
    this.timeoutMs = config.timeoutMs ?? 5000;
  }

  /**
   * Evaluate an HTTP request against the Chio kernel.
   * Returns the verdict and a signed receipt.
   */
  async evaluate(
    request: ChioHttpRequest,
    capabilityToken?: string,
  ): Promise<EvaluateResponse> {
    const url = `${this.baseUrl}/chio/evaluate`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (capabilityToken != null && capabilityToken.length > 0) {
      headers["X-Chio-Capability"] = capabilityToken;
    }

    try {
      const response = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      if (!response.ok) {
        const body = await response.text().catch(() => "");
        throw new SidecarError(
          "chio_evaluation_failed",
          `sidecar returned ${response.status}: ${body}`,
          response.status,
        );
      }

      const result = (await response.json()) as EvaluateResponse;
      if (isAllowShapedResult(result)) {
        await this.assertAuthorizedAllowResult(result);
      }
      return result;
    } catch (error) {
      if (error instanceof SidecarError) {
        throw error;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new SidecarError(
          "chio_timeout",
          `sidecar request timed out after ${this.timeoutMs}ms`,
        );
      }
      throw new SidecarError(
        "chio_sidecar_unreachable",
        `failed to reach sidecar at ${this.baseUrl}: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Verify a receipt against the sidecar's trusted kernel authority.
   */
  async verifyReceipt(receipt: HttpReceipt): Promise<VerifyReceiptResponse> {
    const url = `${this.baseUrl}/chio/verify`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(receipt),
        signal: controller.signal,
      });

      const responseBody = await response.text();
      if (!response.ok) {
        throw new SidecarError(
          classifyVerifyNonOk(response.status, responseBody),
          `sidecar verify returned non-200: ${response.status} ${response.statusText}`.trim(),
          response.status,
        );
      }

      // Validate the response shape at runtime; malformed payloads must fail
      // closed, while body-read failures keep their transport classification.
      let parsed: unknown;
      try {
        parsed = JSON.parse(responseBody) as unknown;
      } catch (error: unknown) {
        throw new SidecarError(
          CHIO_ERROR_CODES.EVALUATION_FAILED,
          `failed to decode verify response: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      if (isVerifyReceiptResponse(parsed)) {
        return parsed;
      }
      throw new SidecarError(
        CHIO_ERROR_CODES.EVALUATION_FAILED,
        "sidecar verify response missing structured authority fields",
      );
    } catch (error) {
      if (error instanceof SidecarError) {
        throw error;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new SidecarError(
          CHIO_ERROR_CODES.TIMEOUT,
          `sidecar verify timed out after ${this.timeoutMs}ms`,
        );
      }
      throw new SidecarError(
        CHIO_ERROR_CODES.SIDECAR_UNREACHABLE,
        `failed to reach sidecar at ${this.baseUrl}: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  private async assertAuthorizedAllowResult(result: EvaluateResponse): Promise<void> {
    if (!isAllowed(result.verdict) || !isAuthorizedHttpReceipt(result.receipt)) {
      throw new SidecarError(
        CHIO_ERROR_CODES.INVALID_RECEIPT,
        "sidecar returned an allow-shaped response without an authoritative Chio receipt",
      );
    }

    const verification = await this.verifyReceipt(result.receipt);
    if (!isAuthoritativeVerification(verification, result.receipt)) {
      throw new SidecarError(
        CHIO_ERROR_CODES.INVALID_RECEIPT,
        "sidecar returned an unverified allow receipt",
      );
    }
  }

  /**
   * Health check for the sidecar.
   */
  async healthCheck(): Promise<boolean> {
    const url = `${this.baseUrl}/chio/health`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method: "GET",
        signal: controller.signal,
      });
      return response.ok;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }
}

function isAllowShapedResult(result: EvaluateResponse): boolean {
  return isAllowed(result.verdict) || (result.receipt != null && isAllowed(result.receipt.verdict));
}

function isSidecarTransportFailure(statusCode: number): boolean {
  return statusCode === 408 || (statusCode >= 500 && statusCode <= 599);
}

function classifyVerifyNonOk(statusCode: number, body: string): string {
  if (hasDefinitiveInvalidReceiptBody(body)) {
    return CHIO_ERROR_CODES.INVALID_RECEIPT;
  }
  if (isSidecarTransportFailure(statusCode) || statusCode === 404 || statusCode === 429) {
    return CHIO_ERROR_CODES.SIDECAR_UNAVAILABLE;
  }
  return CHIO_ERROR_CODES.EVALUATION_FAILED;
}

function hasDefinitiveInvalidReceiptBody(body: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body) as unknown;
  } catch {
    return false;
  }

  return (
    typeof parsed === "object" &&
    parsed !== null &&
    (("valid" in parsed && (parsed as { valid: unknown }).valid === false) ||
      ("error" in parsed &&
        (parsed as { error: unknown }).error === CHIO_ERROR_CODES.INVALID_RECEIPT))
  );
}
