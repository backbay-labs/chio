import { z } from "zod";
import {
  AgentIdSchema,
  RoleSchema,
  SetupSchema,
  type Role,
} from "./setup-code";

export const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/);
export const IdSchema = z.string().uuid();
export const ArtifactIdSchema = z.string().regex(/^[a-z0-9][a-z0-9_.-]{0,95}$/);
const text = z.string().max(64_000);
export const PhaseSchema = z.enum([
  "setup",
  "ready",
  "research",
  "implementation",
  "review",
  "awaiting_review",
  "published",
  "blocked",
  "interrupted",
  "unknown",
]);
export type Phase = z.infer<typeof PhaseSchema>;
export type Document = "changes" | "tests" | "source";
export type Selection = { kind: "role"; role: Role } | { kind: "project" };

export const ArtifactSchema = z.object({
  id: ArtifactIdSchema,
  label: z.string().max(160),
  kind: z.enum([
    "original",
    "candidate",
    "harness",
    "test-output",
    "compiler-output",
    "review",
    "published",
  ]),
  status: z.enum(["available", "pending", "unavailable"]),
  digest: DigestSchema.nullable(),
  digest_scheme: z.literal("canonical-json-sha256"),
  operation_id: z.string().max(128).nullable(),
});
export type Artifact = z.infer<typeof ArtifactSchema>;
export const ArtifactContentSchema = z.object({
  schema_version: z.literal(1),
  mission_id: IdSchema,
  artifact: ArtifactSchema,
  content: text,
  truncated: z.boolean(),
});
export type ArtifactContent = z.infer<typeof ArtifactContentSchema>;

export const TestResultSchema = z.object({
  status: z.enum([
    "pending",
    "passed",
    "failed",
    "compile_failed",
    "runner_failed",
    "unknown",
  ]),
  checks: z
    .array(
      z.object({
        name: z.string().max(256),
        status: z.enum(["passed", "failed", "ignored"]),
      }),
    )
    .max(512),
  output: text.nullable(),
  compiler_output: text.nullable(),
  candidate_digest: DigestSchema.nullable(),
  harness_digest: DigestSchema,
  complete: z.boolean(),
});
export type TestResult = z.infer<typeof TestResultSchema>;
export const ProposalSchema = z.object({
  candidate_id: IdSchema,
  candidate_digest: DigestSchema,
  harness_digest: DigestSchema,
  source_digest: DigestSchema,
  test_receipt: z.string().max(128),
  review_receipt: z.string().max(128),
});
export const PublicationSchema = z.object({
  candidate_digest: DigestSchema,
  destination: z.string().max(4096),
});
export const MissionReferenceSchema = z.object({
  id: IdSchema,
  label: z.string().max(160),
  parent_id: IdSchema.nullable(),
  recipe: z.literal("singleton-window-v1").nullable(),
  revision_id: IdSchema,
});
export const MissionSchema = z.object({
  id: IdSchema,
  label: z.string().max(160),
  phase: PhaseSchema,
  mode: z.enum(["reference", "native", "model"]),
  agents: z
    .object({
      research: AgentIdSchema,
      implementation: AgentIdSchema,
      review: AgentIdSchema,
    })
    .nullable(),
  source_digest: DigestSchema,
  harness_digest: DigestSchema,
  input_identity: DigestSchema,
  artifacts: z.array(ArtifactSchema).max(64),
  tests: TestResultSchema,
  proposal: ProposalSchema.nullable(),
  publication: PublicationSchema.nullable(),
  allowance: z
    .object({
      remaining: z.number().int().nonnegative(),
      total: z.number().int().positive(),
    })
    .nullable(),
  active_role: RoleSchema.nullable(),
});
export type Mission = z.infer<typeof MissionSchema>;

export const ReadinessSchema = z.object({
  id: z.string().max(80),
  label: z.string().max(160),
  status: z.enum(["ready", "missing", "unsupported", "unverified", "error"]),
  blocking: z.boolean(),
  message: z.string().max(2048),
  agent: AgentIdSchema.optional(),
  guide: z.enum(["installation", "native-agents"]).optional(),
});
export type Readiness = z.infer<typeof ReadinessSchema>;
export const CommandTypeSchema = z.enum([
  "prepare_agent",
  "initialize",
  "run",
  "resume",
  "approve",
  "create_revision",
]);
export const CommandObservationSchema = z.object({
  request_id: IdSchema,
  workspace_id: IdSchema,
  mission_id: IdSchema.nullable(),
  type: CommandTypeSchema,
  status: z.enum([
    "accepted",
    "running",
    "succeeded",
    "failed",
    "interrupted",
    "unknown",
  ]),
  message: z.string().max(2048),
  result_mission_id: IdSchema.nullable(),
});
export type CommandObservation = z.infer<typeof CommandObservationSchema>;
export const CommandRequestSchema = z
  .object({
    schema_version: z.literal(1),
    request_id: IdSchema,
    workspace_id: IdSchema,
    mission_id: IdSchema.nullable(),
    expected: z
      .object({
        host_epoch: IdSchema,
        mission_input_identity: DigestSchema.optional(),
        candidate_digest: DigestSchema.optional(),
      })
      .strict(),
    command: z.discriminatedUnion("type", [
      z
        .object({ type: z.literal("prepare_agent"), agent: AgentIdSchema })
        .strict(),
      z.object({ type: z.literal("initialize"), setup: SetupSchema }).strict(),
      z.object({ type: z.literal("run") }).strict(),
      z.object({ type: z.literal("resume") }).strict(),
      z
        .object({ type: z.literal("approve"), candidate_digest: DigestSchema })
        .strict(),
      z
        .object({
          type: z.literal("create_revision"),
          recipe: z.literal("singleton-window-v1"),
        })
        .strict(),
    ]),
  })
  .strict();
export type CommandRequest = z.infer<typeof CommandRequestSchema>;

export const StateSchema = z
  .object({
    schema_version: z.literal(1),
    host: z.object({
      epoch: IdSchema,
      operator_version: z.string().max(80),
      ui_build_id: z.string().max(128),
      target: z.string().max(100),
    }),
    workspace: z.object({
      id: IdSchema,
      schema_version: z.literal(1),
      selected_mission_id: IdSchema.nullable(),
      setup: SetupSchema,
      missions: z.array(MissionReferenceSchema).max(32),
    }),
    capabilities: z.object({
      commands: z.array(CommandTypeSchema).max(6),
      reference: z.boolean(),
      native: z.boolean(),
      native_teams: z
        .array(
          z.object({
            research: AgentIdSchema,
            implementation: AgentIdSchema,
            review: AgentIdSchema,
          }),
        )
        .max(64),
    }),
    readiness: z.array(ReadinessSchema).max(32),
    mission: MissionSchema.nullable(),
    snapshot_id: DigestSchema,
    last_event_sequence: z.number().int().nonnegative(),
    active_command: CommandObservationSchema.nullable(),
  })
  .superRefine((value, ctx) => {
    if (value.workspace.selected_mission_id !== (value.mission?.id ?? null))
      ctx.addIssue({
        code: "custom",
        message: "Snapshot mission does not match selection",
      });
    if (
      value.mission &&
      !value.workspace.missions.some(
        (mission) => mission.id === value.mission!.id,
      )
    )
      ctx.addIssue({ code: "custom", message: "Mission is outside workspace" });
    const mission = value.mission;
    if (
      mission?.proposal &&
      (mission.proposal.source_digest !== mission.source_digest ||
        mission.proposal.harness_digest !== mission.harness_digest)
    )
      ctx.addIssue({
        code: "custom",
        message: "Proposal input identity mismatch",
      });
    if (
      mission?.tests.harness_digest !== undefined &&
      mission.tests.harness_digest !== mission.harness_digest
    )
      ctx.addIssue({
        code: "custom",
        message: "Test harness identity mismatch",
      });
    if (
      mission?.publication &&
      (!mission.proposal ||
        mission.publication.candidate_digest !==
          mission.proposal.candidate_digest)
    )
      ctx.addIssue({
        code: "custom",
        message: "Publication candidate mismatch",
      });
    if (mission?.phase === "published" && !mission.publication)
      ctx.addIssue({
        code: "custom",
        message: "Published phase lacks retained publication",
      });
    if (
      mission?.tests.status === "passed" &&
      (!mission.tests.complete ||
        mission.tests.checks.some((check) => check.status === "failed"))
    )
      ctx.addIssue({
        code: "custom",
        message: "Passing tests have incomplete or contradictory evidence",
      });
  });
export type State = z.infer<typeof StateSchema>;

export const EventSchema = z.object({
  sequence: z.number().int().positive(),
  kind: z.string().max(160),
  actor: z.string().max(160),
  detail: z.record(z.string(), z.unknown()),
});
export const EventBatchSchema = z.object({
  schema_version: z.literal(1),
  host_epoch: IdSchema,
  mission_id: IdSchema,
  events: z.array(EventSchema).max(128),
  has_more: z.boolean(),
  last_sequence: z.number().int().nonnegative(),
});
export type EventBatch = z.infer<typeof EventBatchSchema>;

export type WorkshopSource =
  | {
      kind: "recorded";
      recordId: string;
      mode: "reference";
      qualification: string;
      canMutate: false;
    }
  | {
      kind: "local";
      workspaceId: string;
      hostEpoch: string;
      missionId: string | null;
      freshness: "current" | "stale" | "unknown";
      observedAt: string;
    };

export type RecordedWorkshop = {
  source: Extract<WorkshopSource, { kind: "recorded" }>;
  label: string;
  original: string;
  candidate: string;
  harness: string;
  regression: string;
  tests: TestResult;
  proposal: z.infer<typeof ProposalSchema>;
  published: false;
  archiveDigest: string;
};
