/**
 * Chio sidecar HTTP client.
 *
 * Communicates with the Chio Rust kernel running as a localhost sidecar.
 * The sidecar exposes a POST /chio/evaluate endpoint that accepts an
 * ChioHttpRequest and returns an EvaluateResponse with a signed receipt.
 */

import { CHIO_ERROR_CODES } from "./types.js";
import type {
  ChioConfig,
  ChioHttpRequest,
  EvaluateResponse,
  HttpReceipt,
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
   * Verify a receipt signature against the sidecar.
   * Returns true if the receipt is valid.
   */
  async verifyReceipt(receipt: HttpReceipt): Promise<boolean> {
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

      if (!response.ok) {
        throw new SidecarError(
          isSidecarTransportFailure(response.status)
            ? CHIO_ERROR_CODES.SIDECAR_UNAVAILABLE
            : CHIO_ERROR_CODES.INVALID_RECEIPT,
          `sidecar verify returned non-200: ${response.status} ${response.statusText}`.trim(),
          response.status,
        );
      }

      const responseBody = await response.text();
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
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "valid" in parsed &&
        typeof (parsed as { valid: unknown }).valid === "boolean"
      ) {
        return (parsed as { valid: boolean }).valid;
      }
      throw new SidecarError(
        CHIO_ERROR_CODES.EVALUATION_FAILED,
        "sidecar verify response missing boolean `valid` field",
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

function isSidecarTransportFailure(statusCode: number): boolean {
  return statusCode === 408 || (statusCode >= 500 && statusCode <= 599);
}
