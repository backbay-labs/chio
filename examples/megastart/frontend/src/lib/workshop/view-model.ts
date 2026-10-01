import type {
  ArtifactContent,
  Mission,
  RecordedWorkshop,
  State,
  WorkshopSource,
} from "./schema";
export type WorkshopModel = {
  source: WorkshopSource;
  label: string;
  phase: string;
  original: string | null;
  candidate: string | null;
  harness: string | null;
  tests: Mission["tests"] | null;
  proposal: Mission["proposal"];
  publication: Mission["publication"];
  agents: Mission["agents"];
  activeRole: Mission["active_role"];
};
export function fromRecording(record: RecordedWorkshop): WorkshopModel {
  return {
    ...record,
    phase: "awaiting_review",
    publication: null,
    agents: null,
    activeRole: null,
  };
}
export function fromLocal(
  state: State,
  artifacts: Record<string, ArtifactContent>,
  freshness: "current" | "stale" | "unknown",
  observedAt: string,
): WorkshopModel {
  const mission = state.mission;
  const content = (id: string): string | null => {
    const received = artifacts[id];
    const descriptor = mission?.artifacts.find(
      (item) => item.id === id && item.status === "available",
    );
    return received &&
      descriptor &&
      received.mission_id === mission?.id &&
      received.artifact.digest === descriptor.digest &&
      !received.truncated
      ? received.content
      : null;
  };
  return {
    source: {
      kind: "local",
      workspaceId: state.workspace.id,
      hostEpoch: state.host.epoch,
      missionId: mission?.id ?? null,
      freshness,
      observedAt,
    },
    label: mission?.label ?? "Moving average",
    phase: mission?.phase ?? "setup",
    original: content("original"),
    candidate: content("candidate"),
    harness: content("harness"),
    tests: mission?.tests ?? null,
    proposal: mission?.proposal ?? null,
    publication: mission?.publication ?? null,
    agents: mission?.agents ?? null,
    activeRole: mission?.active_role ?? null,
  };
}
