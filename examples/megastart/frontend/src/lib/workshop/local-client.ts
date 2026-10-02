import {
  ArtifactContentSchema,
  CommandObservationSchema,
  StateSchema,
  type ArtifactContent,
  type CommandObservation,
  type CommandRequest,
  type State,
} from "./schema";
import { actionAvailability, advanceEvents } from "./presentation";
import { sourceDigest } from "./recorded-adapter";
export type Observation = {
  state: State | null;
  artifacts: Record<string, ArtifactContent>;
  freshness: "current" | "stale" | "unknown";
  observedAt: string;
  error: string | null;
  pending: CommandObservation | null;
};
const INITIAL: Observation = {
  state: null,
  artifacts: {},
  freshness: "unknown",
  observedAt: "",
  error: null,
  pending: null,
};

export class HostError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}
export async function boundedJson(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader)
    throw new HostError("INVALID_RESPONSE", "The host returned no data.");
  let size = 0;
  const parts: Uint8Array[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 2_000_000) {
        await reader.cancel();
        throw new HostError(
          "RESPONSE_LIMIT",
          "The host response exceeds the display limit.",
        );
      }
      parts.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

/** One browser intent produces at most one POST. Reconnection is read-only. */
export class LocalClient {
  private value: Observation = { ...INITIAL };
  private listeners = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private generation = 0;
  private stopped = true;
  private selected: string | null = null;
  private pendingId: string | null = null;
  private pendingTarget: string | null = null;
  private cursor: {
    missionId: string;
    hostEpoch: string;
    after: number;
  } | null = null;
  private sending = false;
  private refreshAgain = false;
  private reading = false;
  private readController: AbortController | null = null;
  private failures = 0;
  private visibilityChanged = () => {
    if (!document.hidden && !this.stopped) void this.refresh();
  };
  constructor(
    private token: string,
    private uiBuildId?: string,
    private fetcher: typeof fetch = globalThis.fetch.bind(globalThis),
  ) {}
  snapshot = () => this.value;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  private set(update: Partial<Observation>) {
    this.value = { ...this.value, ...update };
    this.listeners.forEach((listener) => listener());
  }
  start() {
    if (!this.stopped) return;
    this.stopped = false;
    if (typeof document !== "undefined")
      document.addEventListener("visibilitychange", this.visibilityChanged);
    void this.refresh();
  }
  stop() {
    this.stopped = true;
    this.generation++;
    this.refreshAgain = false;
    this.readController?.abort();
    if (typeof document !== "undefined")
      document.removeEventListener("visibilitychange", this.visibilityChanged);
    if (this.timer) clearTimeout(this.timer);
  }
  select(mission: string) {
    if (mission === this.selected) return;
    this.selected = mission;
    this.generation++;
    this.readController?.abort();
    this.cursor = null;
    this.set({ freshness: "stale" });
    void this.refresh();
  }
  private async request(
    path: string,
    init: RequestInit = {},
    readSignal?: AbortSignal,
  ): Promise<unknown> {
    const response = await this.fetcher(`/api/workshop/v1/${path}`, {
      ...init,
      redirect: "error",
      cache: "no-store",
      credentials: "omit",
      signal: readSignal
        ? AbortSignal.any([readSignal, AbortSignal.timeout(12_000)])
        : AbortSignal.timeout(12_000),
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(init.body ? { "Content-Type": "application/json" } : {}),
      },
    });
    const result = await boundedJson(response);
    if (!response.ok) {
      const error = result as { error?: { code?: string; message?: string } };
      throw new HostError(
        error.error?.code ?? "HOST_ERROR",
        error.error?.message ?? "The host refused this request.",
      );
    }
    return result;
  }
  async refresh() {
    if (this.stopped) return;
    if (this.reading) {
      this.refreshAgain = true;
      return;
    }
    this.reading = true;
    const controller = new AbortController();
    this.readController = controller;
    const generation = this.generation;
    if (this.timer) clearTimeout(this.timer);
    try {
      const suffix = this.selected
        ? `?mission=${encodeURIComponent(this.selected)}`
        : "";
      const state = StateSchema.parse(
        await this.request(`state${suffix}`, {}, controller.signal),
      );
      if (generation !== this.generation || this.stopped) return;
      if (this.uiBuildId && state.host.ui_build_id !== this.uiBuildId)
        throw new HostError(
          "INCOMPATIBLE_UI",
          "The interface and host versions differ. Reopen the workshop using the matching installed release.",
        );
      if (
        this.cursor &&
        this.cursor.hostEpoch === state.host.epoch &&
        this.cursor.missionId === state.mission?.id
      ) {
        const events = await this.request(
          `events?mission=${this.cursor.missionId}&after=${this.cursor.after}`,
          {},
          controller.signal,
        );
        this.cursor = {
          ...this.cursor,
          after: advanceEvents(events, this.cursor).cursor,
        };
      } else {
        this.cursor = state.mission
          ? {
              missionId: state.mission.id,
              hostEpoch: state.host.epoch,
              after: state.last_event_sequence,
            }
          : null;
      }
      const artifacts: Record<string, ArtifactContent> = {};
      if (state.mission) {
        await Promise.all(
          state.mission.artifacts
            .filter(
              (item) =>
                ["original", "candidate", "harness"].includes(item.id) &&
                item.status === "available",
            )
            .map(async (descriptor) => {
              const cached = this.value.artifacts[descriptor.id];
              if (
                cached?.mission_id === state.mission!.id &&
                cached.artifact.digest === descriptor.digest
              ) {
                artifacts[descriptor.id] = cached;
                return;
              }
              const artifact = ArtifactContentSchema.parse(
                await this.request(
                  `artifacts/${descriptor.id}?mission=${state.mission!.id}`,
                  {},
                  controller.signal,
                ),
              );
              if (
                artifact.mission_id !== state.mission!.id ||
                artifact.artifact.id !== descriptor.id ||
                artifact.artifact.digest !== descriptor.digest ||
                artifact.truncated ||
                (await sourceDigest(artifact.content)) !== descriptor.digest
              )
                throw new HostError(
                  "ARTIFACT_CHANGED",
                  "An artifact changed during inspection. Refresh before continuing.",
                );
              artifacts[descriptor.id] = artifact;
            }),
        );
      }
      let pending = this.value.pending;
      if (this.pendingId && !this.sending) {
        try {
          pending = CommandObservationSchema.parse(
            await this.request(
              `commands/${this.pendingId}`,
              {},
              controller.signal,
            ),
          );
        } catch (error) {
          if (!(error instanceof HostError) || error.code !== "UNKNOWN_OUTCOME")
            throw error;
          // Keep the unknown intent visible and blocked. This read still
          // establishes a current mission snapshot for inspection and recovery.
          pending = this.value.pending
            ? {
                ...this.value.pending,
                status: "unknown",
                message:
                  "No accepted record was found for this decision. Inspect the mission, then reopen the host before making a new decision.",
              }
            : null;
        }
        if (!pending)
          throw new HostError(
            "UNKNOWN_OUTCOME",
            "The decision could not be reconciled.",
          );
        if (
          pending.workspace_id !== state.workspace.id ||
          pending.request_id !== this.pendingId
        )
          throw new HostError(
            "COMMAND_CHANGED",
            "The host returned another operation's status.",
          );
        if (["succeeded", "failed", "interrupted"].includes(pending.status)) {
          if (
            pending.status === "succeeded" &&
            pending.result_mission_id &&
            this.pendingTarget ===
              (this.selected ?? this.value.state?.mission?.id ?? null)
          ) {
            if (state.mission?.id !== pending.result_mission_id) {
              this.selected = pending.result_mission_id;
              this.cursor = null;
              this.refreshAgain = true;
            }
          }
          this.pendingId = null;
        }
      }
      if (generation !== this.generation || this.stopped) return;
      this.failures = 0;
      this.set({
        state,
        artifacts,
        freshness: "current",
        observedAt: new Date().toISOString(),
        error: null,
        pending,
      });
    } catch (error) {
      if (generation !== this.generation || this.stopped) return;
      this.failures++;
      this.cursor = null;
      this.set({
        freshness: this.value.state ? "stale" : "unknown",
        error:
          error instanceof HostError
            ? error.message
            : "The local host could not be reached or its response could not be verified. Retained work stays visible; controls will return after a successful refresh.",
      });
    } finally {
      this.reading = false;
      if (this.readController === controller) this.readController = null;
      if (!this.stopped) {
        const delay = this.refreshAgain
          ? 0
          : typeof document !== "undefined" && document.hidden
            ? 8000
            : Math.min(
                8000,
                this.failures
                  ? 1000 * 2 ** this.failures
                  : this.pendingId || this.value.state?.active_command
                    ? 750
                    : 1500,
              );
        this.refreshAgain = false;
        this.timer = setTimeout(() => void this.refresh(), delay);
      }
    }
  }
  async send(command: CommandRequest["command"]): Promise<void> {
    const state = this.value.state;
    if (!state || this.sending || this.pendingId) return;
    const allowed = actionAvailability(
      state,
      command.type,
      this.value.freshness,
    );
    if (!allowed.enabled) {
      this.set({ error: allowed.reason });
      return;
    }
    const request: CommandRequest = {
      schema_version: 1,
      request_id: crypto.randomUUID(),
      workspace_id: state.workspace.id,
      mission_id:
        command.type === "initialize" ? null : (state.mission?.id ?? null),
      expected: {
        host_epoch: state.host.epoch,
        ...(state.mission
          ? { mission_input_identity: state.mission.input_identity }
          : {}),
        ...(command.type === "approve"
          ? { candidate_digest: command.candidate_digest }
          : {}),
      },
      command,
    };
    this.sending = true;
    this.pendingId = request.request_id;
    this.pendingTarget = request.mission_id;
    this.set({
      pending: {
        request_id: request.request_id,
        workspace_id: request.workspace_id,
        mission_id: request.mission_id,
        type: command.type,
        status: "unknown",
        message: "Waiting for the host to accept this decision.",
        result_mission_id: null,
      },
      error: null,
    });
    try {
      const pending = CommandObservationSchema.parse(
        await this.request("commands", {
          method: "POST",
          body: JSON.stringify(request),
        }),
      );
      if (
        pending.request_id !== request.request_id ||
        pending.workspace_id !== request.workspace_id
      )
        throw new HostError(
          "COMMAND_CHANGED",
          "The host returned an unrelated operation.",
        );
      this.set({ pending });
    } catch (error) {
      // A definite typed rejection did not accept this request. A lost response
      // remains unknown and is reconciled by GET; neither branch resubmits.
      if (
        error instanceof HostError &&
        !["COMMAND_CHANGED", "INVALID_RESPONSE", "RESPONSE_LIMIT"].includes(
          error.code,
        )
      ) {
        this.pendingId = null;
        if (this.value.pending)
          this.set({
            pending: {
              ...this.value.pending,
              status: "failed",
              message: error.message,
            },
          });
      }
      this.set({
        freshness: "stale",
        error:
          error instanceof HostError
            ? error.message
            : "The response was interrupted. Checking this same decision with the host; it will not be submitted again.",
      });
    } finally {
      this.sending = false;
      void this.refresh();
    }
  }
}
