export interface ChioDenialBody {
  error: "chio_denied";
  reason: string;
  receipt_id?: string | undefined;
}

export interface ChioDenialOptions {
  reason?: string | undefined;
  receiptId?: string | undefined;
  status?: number | undefined;
}

export function createDenialResponse(options: ChioDenialOptions = {}): Response {
  const body: ChioDenialBody = {
    error: "chio_denied",
    reason: options.reason ?? "Chio denied the request",
  };
  if (options.receiptId != null) {
    body.receipt_id = options.receiptId;
  }
  return Response.json(body, {
    status: options.status ?? 403,
    headers: {
      "x-chio-verdict": "deny",
      ...(options.receiptId != null ? { "x-chio-receipt-id": options.receiptId } : {}),
    },
  });
}
