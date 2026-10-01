import {
  type CommandRequest,
  type State,
  type Selection,
  type Document,
  type EventBatch,
  EventBatchSchema,
} from "./schema";

export function documentFor(selection: Selection): Document {
  return selection.kind === "project" || selection.role === "research"
    ? "source"
    : selection.role === "review"
      ? "tests"
      : "changes";
}

export type ActionAvailability = { enabled: boolean; reason: string | null };
export function actionAvailability(
  state: State,
  type: CommandRequest["command"]["type"],
  freshness: "current" | "stale" | "unknown",
): ActionAvailability {
  const no = (reason: string): ActionAvailability => ({
    enabled: false,
    reason,
  });
  if (freshness !== "current")
    return no("Reconnect to the host before changing this workshop.");
  if (!state.capabilities.commands.includes(type))
    return no("This host does not support that action.");
  if (
    state.active_command &&
    ["accepted", "running", "unknown"].includes(state.active_command.status)
  )
    return no("Wait for the pending operation to resolve.");
  if (type === "prepare_agent")
    return state.capabilities.native
      ? { enabled: true, reason: null }
      : no("Native agents are unavailable on this host.");
  const blockers = state.readiness.filter(
    (check) => check.blocking && check.status !== "ready",
  );
  if (["initialize", "run", "resume"].includes(type) && blockers.length)
    return no(blockers[0].message);
  if (type === "initialize")
    return state.mission
      ? no("This mission is already initialized.")
      : { enabled: true, reason: null };
  const mission = state.mission;
  if (!mission) return no("Initialize a mission first.");
  if (type === "run")
    return mission.phase === "ready"
      ? { enabled: true, reason: null }
      : no("This mission is not ready to start.");
  if (type === "resume")
    return ["interrupted", "blocked"].includes(mission.phase)
      ? { enabled: true, reason: null }
      : no("This mission does not need to resume.");
  if (type === "approve") {
    if (
      mission.phase !== "awaiting_review" ||
      !mission.proposal ||
      mission.publication
    )
      return no("No unpublished candidate is ready for approval.");
    if (
      mission.tests.status !== "passed" ||
      !mission.tests.complete ||
      mission.tests.candidate_digest !== mission.proposal.candidate_digest
    )
      return no("Review the complete results for this exact candidate first.");
  }
  if (type === "create_revision") {
    const reference = state.workspace.missions.find(
      (item) => item.id === mission.id,
    );
    if (
      reference?.recipe ||
      !["awaiting_review", "published"].includes(mission.phase) ||
      mission.tests.status !== "passed" ||
      !mission.tests.complete
    )
      return no("Complete the baseline example before adding its regression.");
  }
  return { enabled: true, reason: null };
}

/** Validate the complete batch before returning a new cursor. */
export function advanceEvents(
  input: unknown,
  context: { missionId: string; hostEpoch: string; after: number },
): { batch: EventBatch; cursor: number } {
  const batch = EventBatchSchema.parse(input);
  if (
    batch.mission_id !== context.missionId ||
    batch.host_epoch !== context.hostEpoch
  )
    throw new Error("Event context changed; refresh the snapshot.");
  batch.events.forEach((event, index) => {
    if (event.sequence !== context.after + index + 1)
      throw new Error("Event sequence has a gap; refresh the snapshot.");
  });
  const cursor = batch.events.at(-1)?.sequence ?? context.after;
  if (batch.last_sequence !== cursor)
    throw new Error("Event cursor does not match its validated batch.");
  return { batch, cursor };
}
