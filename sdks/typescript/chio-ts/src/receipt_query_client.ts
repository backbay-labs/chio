import { QueryError, TransportError } from "./errors.ts";
import type { ChioReceipt } from "./invariants/receipt.ts";

export interface ReceiptQueryParams {
  capabilityId?: string;
  toolServer?: string;
  toolName?: string;
  outcome?: string;
  since?: number;
  until?: number;
  minCost?: number;
  maxCost?: number;
  agentSubject?: string;
  cursor?: number;
  limit?: number;
}

export interface ReceiptQueryResponse {
  totalCount: number;
  nextCursor?: number;
  receipts: ChioReceipt[];
}

export class ReceiptQueryClient {
  private baseUrl: string;
  private authToken: string;
  private fetchImpl: typeof fetch;

  constructor(baseUrl: string, authToken: string, fetchImpl?: typeof fetch) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.authToken = authToken;
    this.fetchImpl = fetchImpl ?? globalThis.fetch;
  }

  async query(params: ReceiptQueryParams = {}): Promise<ReceiptQueryResponse> {
    const url = new URL(`${this.baseUrl}/v1/receipts/query`);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value));
      }
    }

    let response: Response;
    try {
      response = await this.fetchImpl(url.toString(), {
        method: "GET",
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
    } catch (cause) {
      throw new TransportError("failed to fetch receipts", { cause });
    }

    if (!response.ok) {
      throw new QueryError(
        `receipt query failed with status ${response.status}`,
        response.status,
      );
    }

    return (await response.json()) as ReceiptQueryResponse;
  }

  async *paginate(params: ReceiptQueryParams = {}): AsyncGenerator<ChioReceipt[]> {
    let cursor: number | undefined = params.cursor;
    while (true) {
      const response =
        cursor === undefined
          ? await this.query(params)
          : await this.query({ ...params, cursor });
      if (response.receipts.length > 0) {
        yield response.receipts;
      }
      if (response.nextCursor === undefined || response.nextCursor === null) {
        break;
      }
      cursor = response.nextCursor;
    }
  }
}
