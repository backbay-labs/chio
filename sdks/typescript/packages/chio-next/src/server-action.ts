import { isAuthorizedEvaluation, nonAuthorizingReason, type ChioAuthorityFields } from "./authority.js";

export interface ChioActionEvaluation extends ChioAuthorityFields {
  verdict: "allow" | "deny";
  reason?: string | undefined;
  receiptId?: string | undefined;
}

export type ChioActionEvaluator<Args extends unknown[]> = (...args: Args) =>
  Promise<ChioActionEvaluation> | ChioActionEvaluation;

export type ChioServerAction<Args extends unknown[], Result> = (...args: Args) =>
  Promise<Result> | Result;

export interface WithChioActionOptions<Args extends unknown[]> {
  evaluate: ChioActionEvaluator<Args>;
}

export class ChioActionDeniedError extends Error {
  readonly receiptId: string | undefined;

  constructor(evaluation: ChioActionEvaluation) {
    super(evaluation.reason ?? "Chio denied the server action");
    this.name = "ChioActionDeniedError";
    this.receiptId = evaluation.receiptId;
  }
}

export function withChioAction<Args extends unknown[], Result>(
  action: ChioServerAction<Args, Result>,
  options: WithChioActionOptions<Args>,
): ChioServerAction<Args, Result> {
  return async (...args: Args): Promise<Result> => {
    const evaluation = await options.evaluate(...args);
    if (!isAuthorizedEvaluation(evaluation)) {
      throw new ChioActionDeniedError({
        ...evaluation,
        verdict: "deny",
        reason: nonAuthorizingReason(evaluation.reason),
      });
    }
    return action(...args);
  };
}
