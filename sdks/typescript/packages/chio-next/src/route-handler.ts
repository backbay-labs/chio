import { isAuthorizedEvaluation, nonAuthorizingReason, type ChioAuthorityFields } from "./authority.js";
import { createDenialResponse } from "./denial.js";
import { passThroughStreamingResponse } from "./streaming.js";

export interface ChioRouteEvaluation extends ChioAuthorityFields {
  verdict: "allow" | "deny";
  reason?: string | undefined;
  reasonCode?: string | undefined;
  receiptId?: string | undefined;
}

export type ChioRouteEvaluator = (request: Request) =>
  Promise<ChioRouteEvaluation> | ChioRouteEvaluation;

export type ChioRouteHandler = (request: Request, context?: unknown) =>
  Promise<Response> | Response;

export interface WithChioOptions {
  evaluate: ChioRouteEvaluator;
  denialStatus?: number | undefined;
}

export function withChio(
  handler: ChioRouteHandler,
  options: WithChioOptions,
): ChioRouteHandler {
  return async (request, context) => {
    const evaluation = await options.evaluate(request.clone());
    if (!isAuthorizedEvaluation(evaluation)) {
      return createDenialResponse({
        reason: nonAuthorizingReason(evaluation.reason),
        reasonCode: evaluation.reasonCode,
        receiptId: evaluation.receiptId,
        status: options.denialStatus,
      });
    }
    return passThroughStreamingResponse(await handler(request, context));
  };
}
