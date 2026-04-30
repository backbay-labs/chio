export interface ChioDenialBody {
  error: "chio_denied";
  reason: string;
  reason_code?: string | undefined;
  receipt_id?: string | undefined;
}

export interface ChioDenialOptions {
  reason?: string | undefined;
  reasonCode?: string | undefined;
  receiptId?: string | undefined;
  status?: number | undefined;
}

export function createDenialResponse(options: ChioDenialOptions = {}): Response {
  const body: ChioDenialBody = {
    error: "chio_denied",
    reason: options.reason ?? "Chio denied the request",
  };
  if (options.reasonCode != null) {
    body.reason_code = options.reasonCode;
  }
  if (options.receiptId != null) {
    body.receipt_id = options.receiptId;
  }
  const headers: Record<string, string> = {
    "x-chio-verdict": "deny",
    "cache-control": "no-store",
  };
  if (options.reasonCode != null) {
    headers["x-chio-reason-code"] = options.reasonCode;
  }
  if (options.receiptId != null) {
    headers["x-chio-receipt-id"] = options.receiptId;
  }
  return Response.json(body, {
    status: options.status ?? 403,
    headers,
  });
}
