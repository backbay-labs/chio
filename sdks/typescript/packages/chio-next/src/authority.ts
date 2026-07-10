export interface ChioAuthorityFields {
  decision?: "allow" | "deny" | "cancelled" | "incomplete" | undefined;
  receipt_kind?: "mediated_decision" | "trace_observation" | "advisory_evaluation" | undefined;
  boundary_class?: "prevent" | "detect_only" | "advisory_only" | undefined;
  observation_outcome?: "observed" | "evaluated" | "dropped" | undefined;
  trust_level?: "mediated" | "verified" | "advisory" | undefined;
  result?: string | undefined;
  authorized?: boolean | undefined;
  ok?: boolean | undefined;
  signer_trusted?: boolean | undefined;
  signature_valid?: boolean | undefined;
  receipt_id_valid?: boolean | undefined;
  parameter_hash_valid?: boolean | undefined;
}

function isAuthorizedResult(result: string | undefined): boolean {
  return result === "allow";
}

export function isAuthorizedEvaluation(
  evaluation: ChioAuthorityFields & { verdict: "allow" | "deny" },
): boolean {
  return evaluation.verdict === "allow"
    && evaluation.decision === "allow"
    && evaluation.receipt_kind === "mediated_decision"
    && evaluation.boundary_class === "prevent"
    && evaluation.observation_outcome == null
    && evaluation.trust_level === "mediated"
    && isAuthorizedResult(evaluation.result)
    && evaluation.authorized === true
    && evaluation.ok === true
    && evaluation.signer_trusted === true
    && evaluation.signature_valid === true
    && evaluation.receipt_id_valid === true
    && evaluation.parameter_hash_valid === true;
}

export function nonAuthorizingReason(reason: string | undefined): string {
  return reason ?? "Chio evaluation did not include verified receipt authorization";
}
